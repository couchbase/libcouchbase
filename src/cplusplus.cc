/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Membase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

/**
 * This file includes all of the other source files so that we can try
 * to compile them with a C++ compiler.
 *
 * @author Trond Norbye
 */
#include "internal.h"

extern "C" {
#include "arithmetic.c"
#include "base64.c"
#include "cookie.c"
#include "event.c"
#include "execute.c"
#include "get.c"
#include "handler.c"
#include "instance.c"
#include "packet.c"
#include "remove.c"
#include "server.c"
#include "store.c"
#include "tap.c"
#include "utilities.c"

}
