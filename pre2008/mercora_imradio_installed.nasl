# OpenVAS Vulnerability Test
# $Id: mercora_imradio_installed.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Mercora IMRadio Detection
#
# Authors:
# Josh Zlatin-Amishav
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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

tag_summary = "Mercora IMRadio is installed on the remote host.  Mercora is an Internet
radio tuner that also provides music sharing, instant messaging, chat,
and forum capabilities.  This software may not be suitable for use in a
business environment.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.19585");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  name = "Mercora IMRadio Detection";
  script_name(name);
 
 
  summary = "Checks for Mercora IMRadio";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Peer-To-Peer File Sharing");

  script_copyright("This script is Copyright (C) 2005 Josh Zlatin-Amishav");

  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name : "URL" , value : "http://www.mercora.com/default2.asp");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);


# Look in the registry for evidence of Mercora.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Mercora/DisplayName";
if (get_kb_item(key)) log_message(port:0);
