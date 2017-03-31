###############################################################################
# OpenVAS Vulnerability Test
# $Id$
#
# CPE Support Functions
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Updated By Sharath S <sharaths@secpod.com> On 2009-11-20
#
# Updated By Chandrashekhar B <bchandra@secpod.com>
#            Sharath S <sharaths@secpod.com> On 2009-11-30
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision$
#
###############################################################################

function build_cpe(value, exp, base) {
  local_var res, last;

  if (isnull(value) || isnull(exp) || isnull(base))
      return NULL;

  res = eregmatch(string:value, pattern:exp, icase:1);
  if (res[1]) {
    last = strlen(base) - 1;
    if (":" >!< base[last]) {
      return base;
    } else if (res[1] && res[2]) {
      return string(base, res[1], ":", res[2]);
    } else if (res[1]) {
      return string(base, res[1]);
    }
  }
  return NULL;
}

