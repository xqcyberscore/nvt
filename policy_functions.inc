###############################################################################
# OpenVAS Vulnerability Test support library
# $Id: policy_functions.inc 9512 2018-04-17 14:08:25Z emoss $
#
# Supporting methods for Policy NVTs.
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

function policy_logging(text)
{
  # This function is used by basic policy tests. The silence value is set in
  # compliance_tests.nasl. If you start the test within a standard policy like
  # IT-Grundschutz, the results are silent by default. If you start the basic 
  # policy test by themselves, they are verbose.
  verbose = get_kb_item("Compliance/verbose");
  if(verbose){
    log_message(data:text, port:0);
  }
}
