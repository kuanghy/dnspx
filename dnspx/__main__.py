# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import sys
import logging
from . import log
from .cli import main


if __name__ == "__main__":
    sys.argv[0] = "dnspx"
    try:
        sys.exit(main())
    except Exception as e:
        log.exception(e)
        raise
    finally:
        logging.shutdown()
