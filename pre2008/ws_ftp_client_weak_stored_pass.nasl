# OpenVAS Vulnerability Test
# $Id: ws_ftp_client_weak_stored_pass.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: WS_FTP client weak stored password
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Updated: 03/12/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote host has a version of the WS_FTP client which use a weak
  encryption method to store site password.";

tag_solution = "Upgrade to the newest version of the WS_FTP client
";
# Ref: Bernardo Quintero of Hispasec <bernardo@hispasec.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14597");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(547);
  script_cve_id("CVE-1999-1078");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WS_FTP client weak stored password");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.ipswitch.com/");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

wsFtpDir = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                               "\App Paths\wsftpgui.exe",item:"path");
if(!wsFtpDir){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wsFtpDir);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:wsFtpDir + "\wsftpgui.exe");
ftpVer = GetVer(file:file, share:share);

if(!ftpVer){
  exit(0);
}

# Grep Version <= 2007.0.0.2
if(version_is_less_equal(version:ftpVer, test_version:"2007.0.0.2")){
  security_message(0);
}
