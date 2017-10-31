###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_application_server_unserialize_vuln.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# IBM WebSphere Application Server Unserialize Vulnerability
#
# Authors:
# Shakeel <bshakeel@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806624");
  script_version("$Revision: 7573 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2015-11-17 17:28:17 +0530 (Tue, 17 Nov 2015)");
  script_name("IBM WebSphere Application Server Unserialize Vulnerability");

  script_tag(name: "summary" , value:"The host is running IBM WebSphere
  Application Server and is prone to unserialize vulnerability.");

 script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to presence
  of a deserialization error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  8.5.5.7 and prior.");

  script_tag(name:"solution", value:"No solution or patch was made available for
  at least one year since disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#jboss");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!webVer = get_app_version(cpe:CPE, nofork:TRUE)){
  exit(0);
}

## Check for versions, latest version is 8.5.5.7, Checking less than that
if(version_is_less_equal(version:webVer, test_version:"8.5.5.7"))
{
  report = 'Installed Version:  ' + webVer + '\n' +
           'Solution            None Available' + '\n';
  security_message(data:report, port:0);
  exit(0);
}
