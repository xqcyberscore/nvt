###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jboss_app_server_rce_vuln.nasl 4835 2016-12-22 06:42:42Z antu123 $
#
# JBoss WildFly Application Server Remote Code Execution Vulnerability 
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:redhat:jboss_wildfly_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806623");
  script_version("$Revision: 4835 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-12-22 07:42:42 +0100 (Thu, 22 Dec 2016) $");
  script_tag(name:"creation_date", value:"2015-11-17 16:28:17 +0530 (Tue, 17 Nov 2015)");
  script_name("JBoss WildFly Application Server Remote Code Execution Vulnerability");

  script_tag(name: "summary" , value:"The host is running JBoss WildFly
  Application Server and is prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to presence
  of a deserialization error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"JBoss WildFly Application Server versions
  before 9.0.2");

  script_tag(name:"solution", value:"No solution or patch was made available for
  at least one year since disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#jboss");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jboss_wildfly_detect.nasl");
  script_mandatory_keys("JBoss/WildFly/installed");
  script_require_ports("Services/www", 8080);
  exit(0);
}

##
##  Code Starts Here
##

include("host_details.inc");
include("version_func.inc");

webVer = "";
webPort = "";

if(!webPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!get_port_state(webPort)){
  exit(0);
}

if(!webVer = get_app_version(cpe:CPE, port:webPort)){
  exit(0);
}

if(version_is_less_equal(version:webVer, test_version:"9.0.2"))
{
  report = 'Installed Version:  ' + webVer + '\n' +
           'Solution            None Available' + '\n';
  security_message(data:report, port:webPort);
  exit(0);
}
