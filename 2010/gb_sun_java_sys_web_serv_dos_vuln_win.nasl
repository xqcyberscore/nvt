###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_dos_vuln_win.nasl 8296 2018-01-05 07:28:01Z teissa $
#
# Sun Java System Web Server Denial of Service Vulnerability (Windows)
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation lets the attackers to cause a denial of service
  via HTTP request that lacks a method token or format string specifiers
  in PROPFIND request.
  Impact Level: Application";
tag_affected = "Sun Java System Web Server version 7.0 update 6 on Windows.
  Sun Java System Web Server version 7.0 update 7 on Windows.";
tag_insight = "
  - Format string vulnerability in the WebDAV implementation in webservd that
    can be exploited to cause denial of service via format string specifiers
    in the encoding attribute of the XML declaration in a PROPFIND request.
  - An unspecified error in admin server that can be exploited to cause
    denial of service via an HTTP request that lacks a method token.";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";
tag_summary = "This host has Sun Java Web Server running which is prone to
  Denial of Service Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800161");
  script_version("$Revision: 8296 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0388","CVE-2010-0389");
  script_bugtraq_id(37910);
  script_name("Sun Java System Web Server Denial of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55812");
  script_xref(name : "URL" , value : "http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70-webdav.html");
  script_xref(name : "URL" , value : "http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70-admin.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_sun_java_sys_web_serv_detect.nasl", "secpod_reg_enum.nasl");
  script_mandatory_keys("java_system_web_server/installed", "SMB/WindowsVersion");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Check for Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Check for Sun Java System Web Server 7.0
if(get_kb_item("Sun/JavaSysWebServ/Ver") != "7.0"){
  exit(0);
}

## Get Application Installed Path
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
sjswsPath = registry_get_sz(key:key + "Sun Java System Web Server",
                           item:"UninstallString");

if(sjswsPath != NULL)
{
  ## Construct path to point "WebServer.inf" file
  sjswsPath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:sjswsPath);
  sjswsPath = sjswsPath - "\bin\uninstall.exe" + "\setup\WebServer.inf";

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sjswsPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",string:sjswsPath);

  ## Get file contents
  fileData = read_file(share:share, file:file, offset:0, count:500);

  ## Extract Product Version and Update Version
  sjswsVer = eregmatch(pattern:"PRODUCT_VERSION=([0-9.]+)", string:fileData);
  sjswsUpdateVer = eregmatch(pattern:"PRODUCT_SP_VERSION=([0-9]+)", string:fileData);

  ## Construct Full Product Version
  if(sjswsVer[1] != NULL){
   if(sjswsUpdateVer != NULL)
      sjswsFullVer = sjswsVer[1] + "." + sjswsUpdateVer[1];
    else
      sjswsFullVer = sjswsVer[1] + "." + "0";
  }

  if(sjswsFullVer != NULL)
  {
    ## Check Sun Java System Web Server is equal to 7.0.6 or 7.0.7
    ## i.e Sun Java System Web Server 7 Update 6 / Update 7
    if(version_is_equal(version:sjswsFullVer, test_version:"7.0.6")||
       version_is_equal(version:sjswsFullVer, test_version:"7.0.7"))
    {
      sjswsPort = get_kb_item("Sun/JavaSysWebServ/Port");
      security_message(sjswsPort);
      exit(0);
    }
  }
}
