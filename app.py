# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import sys
from dnspx.cli import main


if __name__ == "__main__":
    sys.argv[0] = "dnspx"
    sys.exit(main())
