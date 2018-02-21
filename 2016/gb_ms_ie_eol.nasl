###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_eol.nasl 8882 2018-02-20 10:35:37Z cfischer $
#
# Microsoft Internet Explorer End Of Life Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806657");
  script_version("$Revision: 8882 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-02-20 11:35:37 +0100 (Tue, 20 Feb 2018) $");
  script_tag(name:"creation_date", value:"2016-01-12 15:30:21 +0530 (Tue, 12 Jan 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Internet Explorer End Of Life Detection");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/lifecycle#gp/Microsoft-Internet-Explorer");

  script_tag(name: "summary" , value: "Check for Internet Explorer version and determine if it has reached end of life");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || !(ieVer =~ "^(6|7|8|9|10|11)")){
  exit(0);
}

## Windows 7 and Server 2008r2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Internet Explorer 11 only supported Windows 7 and Server 2008r2
  ## https://support.microsoft.com/en-us/lifecycle#gp/Microsoft-Internet-Explorer
  if(!(ieVer =~ "^(11)"))
  {
    VULN = TRUE;
    Fix = "Internet Explorer 11";
  }
}

  
## Windows Vista and Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Internet Explorer 9 only supported for Windows Vista and Server 2008
  if(!(ieVer =~ "^(9)"))
  {
    VULN = TRUE;
    Fix = "Internet Explorer 9";
  }
}


## Windows Server 2012
else if(hotfix_check_sp(win2012:1) > 0)
{
  ##Internet Explorer 10 only supported for Windows Server 2012
  if(!(ieVer =~ "^(10)"))
  {
    VULN = TRUE;
    Fix = "Internet Explorer 10";
  }
}

if(VULN)
{
  report = "Internet Explorer detected on the remote host has reached the end of life." + '\n' +
           'IE version Detected:    ' + ieVer  + '\n'+
           'Fixed version:          ' + Fix;
  security_message(data:report);
  exit(0);
}
