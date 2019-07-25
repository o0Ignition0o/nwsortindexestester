#include <iostream>
#include <numeric>
#include <vector>

#include <sys/socket.h>
#include <sys/sysctl.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

//
// Sort the ifIndexes according to the prefixStore and the netmaskStore
//
// Given an array of prefixes and netmasks
// mutate ifIndexes so it contains the indexes of the correctly ordered
// prefixes and netmasks.
//
static void sortIndexes(const in6_addr prefixStore[],
                        const in6_addr netmaskStore[],
                        std::vector<int> &outIfIndexes) {
  std::sort(outIfIndexes.begin(), outIfIndexes.end(),
            [&](const int &a, const int &b) {
              // compare prefixStore
              int comparedPrefix =
                  memcmp(&prefixStore[a], &prefixStore[b], sizeof(in6_addr));
              if (comparedPrefix == 0) {
                // compare netmaskStore
                return memcmp(&netmaskStore[a], &netmaskStore[b],
                              sizeof(in6_addr)) < 0;
              }
              return comparedPrefix < 0;
            });
}

//
// Sort the ifIndexes according to the prefixes and the prefixLengths
//
// Given an array of prefixes and prefixLengths
// mutate ifIndexes so it contains the indexes of the correctly ordered
// prefixes and prefixLengths.
//
static void
sortIndexesLinux(const std::vector<std::vector<unsigned char>> &prefixes,
                      const std::vector<int> &prefixLengths,
                      std::vector<int> &outIfIndexes) {
  std::sort(outIfIndexes.begin(), outIfIndexes.end(),
            [&](const int &a, const int &b) {
              for (auto i = 0; i < std::max(prefixLengths[a], prefixLengths[b]);
                   i++) {
                auto first_prefix = prefixes[a][i];
                auto second_prefix = prefixes[b][i];
                if (first_prefix != second_prefix) {
                  return first_prefix <= second_prefix;
                }
              }
              // Both prefixes are already ordered
              return true;
            });
}

void testSortLinux(void) {

  bool found = false;
  FILE *ifs = fopen("if_inet6", "r");
  if (ifs) {
    char buffer[512];
    char ip6[40];
    int devnum;
    int preflen;
    int scope;
    int flags;
    char name[40];

    // The found IPv6 addresses aren't guaranteed to always be in the same
    // order. We will sort them before we compute a sha1 hash, so that a set of
    // IPs always returns the same hash regardless of the lines order.
    std::vector<std::vector<unsigned char>> prefixes;
    std::vector<int> prefixLengths;
    int prefixCount = 0;

    char *l = fgets(buffer, sizeof(buffer), ifs);
    // 2a001a28120000090000000000000002 02 40 00 80   eth0
    // +------------------------------+ ++ ++ ++ ++   ++
    // |                                |  |  |  |    |
    // 1                                2  3  4  5    6
    //
    // 1. IPv6 address displayed in 32 hexadecimal chars without colons as
    //    separator
    //
    // 2. Netlink device number (interface index) in hexadecimal.
    //
    // 3. Prefix length in hexadecimal number of bits
    //
    // 4. Scope value (see kernel source include/net/ipv6.h and
    //    net/ipv6/addrconf.c for more)
    //
    // 5. Interface flags (see include/linux/rtnetlink.h and net/ipv6/addrconf.c
    //    for more)
    //
    // 6. Device name
    //
    while (l) {
      memset(ip6, 0, sizeof(ip6));
      if (6 == sscanf(buffer, "%32[0-9a-f] %02x %02x %02x %02x %31s", ip6,
                      &devnum, &preflen, &scope, &flags, name)) {
        unsigned char id6[16];
        memset(id6, 0, sizeof(id6));

        for (int i = 0; i < 16; i++) {
          char buf[3];
          buf[0] = ip6[i * 2];
          buf[1] = ip6[i * 2 + 1];
          buf[2] = 0;
          // convert from hex
          id6[i] = (unsigned char)strtol(buf, nullptr, 16);
        }

        unsigned char prefix[16];
        memset(prefix, 0, sizeof(prefix));

        uint8_t maskit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe};
        int bits = preflen;
        for (int i = 0; i < 16; i++) {
          uint8_t mask = (bits >= 8) ? 0xff : maskit[bits];
          prefix[i] = id6[i] & mask;
          bits -= 8;
          if (bits <= 0) {
            break;
          }
        }

        // We add the IPv6 prefix and prefix length in order to
        // differentiate between networks with a different prefix length
        // For example: 2a00:/16 and 2a00:0/32
        ++prefixCount;
        std::vector<unsigned char> currentPrefix(prefix, prefix + preflen / 8);
        prefixes.push_back(currentPrefix);
        prefixLengths.push_back(preflen);

        found = true;
      }
      l = fgets(buffer, sizeof(buffer), ifs);
    }
    fclose(ifs);

    if (prefixCount > 0) {
      // Get the ordered indexes so we can compute a deterministic sha1 sum.
      int prefIndexes[prefixCount];
      // ifIndexes = [0,1,2...prefixCount)
      std::iota(prefIndexes, prefIndexes + prefixCount, 0);
      std::vector<int> vIfIndexes(prefIndexes, prefIndexes + prefixCount);
      std::cout << "before" << std::endl;
      for (auto index : vIfIndexes) {
        std::cout << index << std::endl;
      }
      sortIndexesLinux(prefixes, prefixLengths, vIfIndexes);
      std::cout << "after" << std::endl;
      // Update the hash in the correct order
      for (auto index : vIfIndexes) {
        std::cout << index << std::endl;
      }
    }
  }
}

void testSortMacOs(void) {

  struct sockaddr_in6 ip1, ip2, ip3;
  int prefixCount = 3;

  // store this IP address in sa:
  inet_pton(AF_INET6, "2001:db8:8714:3a91::10", &(ip1.sin6_addr));
  inet_pton(AF_INET6, "2001:db8:8714:3a91::9", &(ip2.sin6_addr));
  inet_pton(AF_INET6, "2001:db8:8714:3a91::12", &(ip3.sin6_addr));

  in6_addr prefixStore[3] = {ip1.sin6_addr, ip2.sin6_addr, ip3.sin6_addr};
  in6_addr netmaskStore[3] = {ip1.sin6_addr, ip2.sin6_addr, ip3.sin6_addr};

  // getifaddrs does not guarantee the interfaces
  // will always be in the same order
  // We want to make sure the hash remains consistent
  // Regardless of the interface order.
  int ifIndexes[prefixCount];
  // ifIndexes = [0,1,2...prefixCount)
  std::iota(ifIndexes, ifIndexes + prefixCount, 0);
  std::vector<int> vIfIndexes(ifIndexes, ifIndexes + prefixCount);
  std::cout << "before" << std::endl;
  for (auto index : vIfIndexes) {
    std::cout << index << std::endl;
  }
  sortIndexes(prefixStore, netmaskStore, vIfIndexes);
  std::cout << "after" << std::endl;
  for (auto index : vIfIndexes) {
    std::cout << index << std::endl;
  }
}

int main() {
  std::cout << "Macos : " << std::endl;
  testSortMacOs();
  std::cout << "Linux : " << std::endl;
  testSortLinux();
}