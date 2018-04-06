###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_bof_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Sun Java System Web Server Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
code in the context of an affected system.

Impact Level: System/Application";

tag_affected = "Sun Java System Web Server version 7.0 update 6 and prior on Windows.";

tag_insight = "An unspecified error and can be exploited to cause a buffer overflow.";

tag_solution = "Upgrade to version 7.0 update 7 or later,
For updates refer to http://www.sun.com/";

tag_summary = "This host has Sun Java Web Server running which is prone to Buffer
Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801146");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-12 15:21:24 +0100 (Thu, 12 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3878");
  script_bugtraq_id(36813);
  script_name("Sun Java System Web Server Buffer Overflow Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://intevydis.com/vd-list.shtml");
  script_xref(name : "URL" , value : "http://www.intevydis.com/blog/?p=79");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37115");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3024");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_sun_java_sys_web_serv_detect.nasl", "secpod_reg_enum.nasl");
  script_mandatory_keys("Sun/JavaSysWebServ/Ver", "SMB/WindowsVersion");
  script_require_ports("Services/www", 80, 8888, 139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

jswsVer = get_kb_item("Sun/JavaSysWebServ/Ver");
if(!jswsVer){
  exit(0);
}

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Sun Microsystems\WebServer")){
  exit(0);
}

if("7.0" >< jswsVer)
{
  jswsPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                 "\Uninstall\Sun Java System Web Server",
                             item:"UninstallString");
  if(jswsPath != NULL)
  {
    jswsPath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:jswsPath);
    jswsPath = jswsPath - "\bin\uninstall.exe" + "\README.TXT";

    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:jswsPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",string:jswsPath);
    jswsVer = read_file(share:share, file:file, offset:0, count:150);

    if(jswsVer != NULL)
    {
      jswsVer = eregmatch(pattern:"Web Server ([0-9.]+)([ a-zA-z]+)?([0-9]+)?",
                          string:jswsVer);
      if(jswsVer[1] != NULL)
      {
        if(jswsVer[3] != NULL)
          jswsVer = jswsVer[1] + "." + jswsVer[3];
        else
         jswsVer = jswsVer[1];
      }
    }
  }
}

if(jswsVer != NULL)
{
  # Check for Web Server version <= 7.0 Update 6
  if(version_is_less_equal(version:jswsVer, test_version:"7.0.6"))
  {
    jswsPort = get_kb_item("Sun/JavaSysWebServ/Port");
    security_message(jswsPort);
  }
}
