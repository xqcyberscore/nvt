# OpenVAS Vulnerability Test
# $Id: plaxo_installed.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Plaxo Client Is Installed
#
# Authors:
# Tom Ferris
#
# Copyright:
# Copyright (C) 2005 Tom Ferris <tommy@security-protocols.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote host has the Plaxo Client software installed. Plaxo is a contact manager.
Make sure its use is compatible with your corporate security policy.";

tag_solution = "Uninstall this software if it does not match your security policy";

# <tommy@security-protocols.com>
# 6/29/2005
# www.security-protocols.com

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.18591");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

 name = "Plaxo Client Is Installed";

 script_name(name);



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");

 script_copyright("This script is Copyright (C) 2005 Tom Ferris <tommy@security-protocols.com>");
 family = "Windows";
 script_family(family);

 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Plaxo/DisplayName";

if (get_kb_item (key))
  log_message(get_kb_item("SMB/transport"));
