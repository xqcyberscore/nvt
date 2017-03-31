###############################################################################
# OpenVAS Vulnerability Test support library
# $Id$
#
# Supporting methods for IT-Grundschutz checks.
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

# itg_id is for example "GSHB-12/M4_339"
function itg_send_details (itg_id)
{
  local_var result, desc, report;

  if( ! itg_id )
  {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#itg_id#-#itg_send_details");
    return;
  }

  result = get_kb_item(string(itg_id + '/result'));
  desc = get_kb_item(string (itg_id + '/desc'));

  report = 'Ergebnis:\t' + result +
           '\nDetails:\t' + desc + '\n\n';

  log_message(port:0, proto: "IT-Grundschutz", data:report);
}
