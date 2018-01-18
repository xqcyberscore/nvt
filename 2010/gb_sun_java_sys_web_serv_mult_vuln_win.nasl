###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_mult_vuln_win.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# Sun Java System Web Server Multiple Vulnerabilities (Windows)
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

tag_impact = "Successful exploitation lets the attackers to discover process memory
locations or execute arbitrary code in the context of an affected system
or cause the application to crash via a long URI in an HTTP OPTIONS request.

Impact Level: System/Application";
tag_affected = "Sun Java System Web Server version 7.0 update 7 on Windows.";
tag_insight = "
  - An error exists in WebDAV implementation in webservd and can be exploited
    to cause Stack-based buffer overflow via long URI in an HTTP OPTIONS
    request.
  - An unspecified error that can be exploited to cause a heap-based buffer
    overflow which allows remote attackers to discover process memory
    locations and execute arbitrary code by sending a process memory address
    via crafted data.
  - An error exists in in webservd and admin server that can be exploited to
    overflow a buffer and execute arbitrary code on the system or cause
    the server to crash via a long string in an 'Authorization: Digest' HTTP
    header.";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";
tag_summary = "This host has Sun Java Web Server running which is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800157");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0360", "CVE-2010-0361", "CVE-2010-0387");
  script_bugtraq_id(37896);
  script_name("Sun Java System Web Server Multiple Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://intevydis.com/sjws_demo.html");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55792");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Jan/1023488.html");
  script_xref(name : "URL" , value : "http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-webdav.html");
  script_xref(name : "URL" , value : "http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-digest.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_sun_java_sys_web_serv_detect.nasl", "secpod_reg_enum.nasl", "gb_sun_java_sys_web_serv_mult_vuln.nasl");
  script_mandatory_keys("java_system_web_server/installed", "SMB/WindowsVersion");
  script_exclude_keys("Sun/JavaSysWebServ/37874");
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

## Check if vulnerability already discovered by remote check
if(get_kb_item("Sun/JavaSysWebServ/37874")){
  exit(0);
}

## Check for Sun Java System Web Server 7.0
if( get_kb_item("Sun/JavaSysWebServ/Ver") != "7.0"){
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
    ## Check Sun Java System Web Server is equal to 7.0.7
    ## i.e Sun Java System Web Server 7 Update 7
    if(version_is_equal(version:sjswsFullVer, test_version:"7.0.7"))
    {
      sjswsPort = get_kb_item("Sun/JavaSysWebServ/Port");
      security_message(sjswsPort);
      exit(0);
    }
  }
}
