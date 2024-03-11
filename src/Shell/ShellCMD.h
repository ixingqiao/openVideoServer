/*
 * Copyright (c) 2016 The ZLMediaKit project authors. All Rights Reserved.
 *
 * This file is part of ZLMediaKit(https://github.com/xia-chu/ZLMediaKit).
 *
 * Use of this source code is governed by MIT license that can be found in the
 * LICENSE file in the root of the source tree. All contributing project authors
 * may be found in the AUTHORS file in the root of the source tree.
 */

#ifndef SRC_SHELL_SHELLCMD_H_
#define SRC_SHELL_SHELLCMD_H_

#include "Util/CMD.h"
using namespace toolkit;

namespace mediakit {


class CMD_media: public CMD {
public:
    CMD_media(){}
    virtual ~CMD_media() {}
    const char *description() const override {
        return "媒体源相关操作.";
    }
};

} /* namespace mediakit */

#endif //SRC_SHELL_SHELLCMD_H_