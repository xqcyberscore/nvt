# OpenVAS
# $Id: lsc_options.nasl 7822 2017-11-20 08:46:09Z cfischer $
# Description: This script allows to set some Options for LSC.
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

tag_summary = "This script allows users to set some Options for Local Security
Checks.

These data are stored in the knowledge base
and used by other tests.";

if(description)
{
 script_id(100509);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 7822 $");
 script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:46:09 +0100 (Mon, 20 Nov 2017) $");
 script_tag(name:"creation_date", value:"2010-02-26 12:01:21 +0100 (Fri, 26 Feb 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Options for Local Security Checks");


 script_category(ACT_SETTINGS);
  script_tag(name:"qod_type", value:"general_note");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_family("Settings");

 # Use find command yes/no
 script_add_preference(name:"Also use 'find' command to search for Applications", type:"checkbox", value:"yes");
 # add -xdev to find yes/no
 script_add_preference(name:"Descend directories on other filesystem (don't add -xdev to find)", type:"checkbox", value:"yes");

 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

find_enabled       = script_get_preference("Also use 'find' command to search for Applications");
nfs_search_enabled = script_get_preference("Descend directories on other filesystem (don't add -xdev to find)");

if (find_enabled) { 
  set_kb_item(name: "ssh/lsc/enable_find", value: find_enabled);
}

if (nfs_search_enabled) {
  set_kb_item(name: "ssh/lsc/descend_ofs", value: nfs_search_enabled);
}

exit(0);
