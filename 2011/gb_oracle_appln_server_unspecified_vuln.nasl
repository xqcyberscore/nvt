###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_appln_server_unspecified_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Oracle Application Server Unspecified Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802531");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2008-0346");
  script_bugtraq_id(27229);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-07 13:09:22 +0530 (Wed, 07 Dec 2011)");
  script_name("Oracle Application Server Unspecified Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_require_ports("Services/www", 7777);
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Oracle-Application-Server/banner");

  script_tag(name:"impact", value:"An unspecified impact and attack vectors.");
  script_tag(name:"affected", value:"Oracle application server version 1.3.1.27");
  script_tag(name:"insight", value:"The flaw is due to unspecified error in the oracle jinitiator
  component.");
  script_tag(name:"solution", value:"Apply patches");
  script_tag(name:"summary", value:"This host is running Oracle application server and is prone to
  unspecified vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/28518");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1019218");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/alerts-086861.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2008-086860.html");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

appPort = get_http_port(default:7777);

banner = get_http_banner(port:appPort);

if(!banner && "Oracle-Application-Server" >!< banner){
  exit(0);
}

appVer = eregmatch(pattern:"Oracle-Application-Server-[0-9a-zA-Z]+?/([0-9.]+)",
                                           string:banner);
if(appVer[1] == NULL){
  exit(0);
}

if(version_is_less(version:appVer[1], test_version:"1.3.1.26"))
{
  security_message(port:appPort);
  exit(0);
}

report = string("***** \n" +
                " NOTE : Ignore this warning, if the mentioned patch" +
                " is already applied.\n" +
                " ***** \n");

if(version_is_equal(version:appVer[1], test_version:"1.3.1.27")){
  security_message(data:report, port:appPort);
  exit(0);
}

exit(99);
