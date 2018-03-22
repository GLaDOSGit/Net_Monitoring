/*******************************************
 * Author(s): Gu Kai <540867841@qq.com>
 *
 * This file is for probe info client.
*******************************************/

#include "probe.h"

#include <fstream>
#include <iostream>
#include <unistd.h>

using namespace std;

int main () {
  fstream infile("/proc/net/dev");
  if (!infile) {
    cout << "error" << endl;
  }
  while (1) {
    infile.clear();
    infile.seekp(0, std::ios::beg);
    while (!infile.eof()) {
      char a;
      infile.get(a);
      cout << a;
    }
    cout << 1 << endl;
    sleep (5);
    cout << 2 << endl;
  }
}
