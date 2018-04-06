###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_n_sjas_sec_bypass_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Oracle GlassFish/System Application Server Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Modified by Michael Meyer <michael.meyer@greenbone.net> 25.08.2010
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow local attackers to execute arbitrary code
  under the context of the application.
  Impact Level: System/Application";
tag_affected = "Oracle GlassFish version 2.1, 2.1.1 and 3.0.1
  Oracle Java System Application Server 9.1";
tag_insight = "The flaw exists in the Web Administration component which listens by default
  on TCP port 4848. When handling a malformed GET request to the administrative
  interface, the application does not properly handle an exception allowing the
  request to proceed without authentication.";
tag_solution = "Apply the security updates.
  http://www.oracle.com/technetwork/topics/security/cpuapr2011-301950.html";
tag_summary = "The host is running GlassFish/System Application Server and is prone
  to security bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801926");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-0807");
  script_bugtraq_id(47438);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Oracle GlassFish/System Application Server Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/47438/discuss");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/cve/CVE-2011-0807");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuapr2011-301950.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("GlassFish_detect.nasl", "secpod_sun_java_app_serv_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Check for the default port
if(!port = get_http_port(default:8080)){
  port = 8080;
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Get the version form KB
vers = get_kb_item(string("www/", port, "/GlassFish"));

if(!isnull(vers))
{

  if(cport = get_kb_item("GlassFishAdminConsole/port")) {

    req = FALSE;

    if (vers =~ "^2")
      req = string("get /applications/upload.jsf HTTP/1.1\r\nHost: ",get_host_name(),"\r\n\r\n");
    else if (vers =~ "^3")
      req = string("get /common/applications/uploadFrame.jsf HTTP/1.1\r\nHost: ",get_host_name(),"\r\n\r\n");

    if(req) {

      buf = http_send_recv(port:cport, data:req, bodyonly:FALSE);

      if(buf != NULL) {

	if(egrep(pattern:"<title>Deploy.*Applications.*Modules</title>", string:buf)) {
         
          security_message(port:cport);

	}  

      }	

    }  

  } else {  

    if(version_is_equal(version: vers, test_version:"3.0.1") ||
       version_in_range(version: vers, test_version:"2.1", test_version2:"2.1.1"))
    {
      security_message(port:port);
    }

  }

}

ver = get_kb_item("Sun/Java/AppServer/Ver");
if(ver)
{
  ver = ereg_replace(pattern:"_", replace:".", string:ver);

  # Check for Java Application Server version 9.1
  if(version_is_equal(version:ver, test_version:"9.0.01")){
    security_message(port:port);
  }
}
