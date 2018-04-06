###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_xss_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Sun Java System Web Server XSS Vulnerability (Windows)
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

tag_impact = "Successful exploitation will lets the attackers to execute arbitrary code,
  gain sensitive information by conducting XSS attacks in the context of a 
  affected site.
  Impact Level: System/Application";
tag_affected = "Sun Java System Web Server versions 6.1 and before 6.1 SP11 on Windows.";
tag_insight = "The Flaw is due to, error in 'Reverse Proxy Plug-in' which is not properly
  sanitized the input data before being returned to the user. This can be
  exploited to inject arbitrary web script or HTML via the query string in
  situations that result in a 502 Gateway error.";
tag_solution = "Update to Web Server version 6.1 SP11
  http://www.sun.com/download/index.jsp
  http://sunsolve.sun.com/search/document.do?assetkey=1-66-259588-1";
tag_summary = "This host has Sun Java Web Server running on Windows, which is prone
  to Cross-Site Scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800811");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1934");
  script_bugtraq_id(35204);
  script_name("Sun Java System Web Proxy Server Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35338");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-21-116648-23-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
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

if(get_kb_item("Sun/JavaSysWebServ/Ver") >!< "6.1"){
  exit(0);
}

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Sun Microsystems\WebServer")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  jswsName = registry_get_sz(key:key + item, item:"DisplayName");
  if(jswsName != NULL && jswsName =~ "Sun (ONE |Java System )Web Server")
  {
    jswsVer = eregmatch(pattern:"Web Server ([0-9.]+)(SP[0-9]+)?",
                        string:jswsName);
    if(jswsVer[1] != NULL)
    {
      if(jswsVer[2] != NULL)
         jswsVer = jswsVer[1] + "." + jswsVer[2];
      else
        jswsVer = jswsVer[1];

      # Grep for versions 6.1 < 6.1SP11
      if(version_in_range(version:jswsVer, test_version:"6.1",
                                           test_version2:"6.1.SP10"))
      {
        jswsPort = get_kb_item("Sun/JavaSysWebServ/Port");
        security_message(jswsPort);
        exit(0);
      }
    }
  }
}
