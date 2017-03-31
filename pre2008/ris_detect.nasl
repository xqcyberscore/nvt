# OpenVAS Vulnerability Test
# $Id: ris_detect.nasl 5452 2017-03-01 08:53:44Z cfi $
# Description: RIS Installation Check
#
# Authors:
# Jeff Adams <jadams@netcentrics.com>
#
# Copyright:
# Copyright (C) 2004 Jorge Pinto And Nelson Gomes
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

tag_summary = "This plugin checks if the equipment was installed via RIS.";

if(description)
{
 script_id(12231);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5452 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-01 09:53:44 +0100 (Wed, 01 Mar 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 name = "RIS Installation Check";
 script_name(name);


 summary = "Checks if the remote host was installed via RIS.";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_copyright("This script is Copyright (C) 2004 Jorge Pinto And Nelson Gomes");
 family = "Windows";
 script_family(family);
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access", "SMB/transport");
 script_require_ports(139, 445);
 script_mandatory_keys("SMB/WindowsVersion");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("smb_nt.inc");

services = get_kb_item("SMB/registry_access");
if ( ! services ) exit(-2);

port = kb_smb_transport();
if(!port)port = 139;


#---------------------------------
# My Main
#---------------------------------

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
item = "SourcePath";
value = registry_get_sz(key:key, item:item);

if(!value) {
        exit(-1);
}

if( match(string:value, pattern:'*RemInst*')  ){
        report = "The remote host was installed using RIS (Remote Installation Service).";
        log_message(port:port, data:report);
        exit(1);
}

exit(0);
