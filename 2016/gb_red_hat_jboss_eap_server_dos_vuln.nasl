###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_red_hat_jboss_eap_server_dos_vuln.nasl 7191 2017-09-20 04:14:22Z ckuersteiner $
#
# Red Hat JBoss EAP Server Denial of Service Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:redhat:jboss_enterprise_application_platform";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810307");
  script_version("$Revision: 7191 $");
  script_cve_id("CVE-2016-7065");
  script_bugtraq_id(93462);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-09-20 06:14:22 +0200 (Wed, 20 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-12-09 12:42:39 +0530 (Fri, 09 Dec 2016)");
  script_name("Red Hat JBoss EAP Server Denial of Service Vulnerability");

  script_tag(name:"summary", value:"This host is running Red Hat JBoss EAP Server
  and is prone to denial of service Vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to JMX servlet
  deserializes Java objects sent via HTTP.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to cause a denial of service and possibly execute
  arbitrary code.

  Impact Level: Application");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"Red Hat JBoss EAP server version 4 and 5.");

  script_tag(name:"solution", value:"Red Hat marked this vulnerability as 'Will not fix' (see
https://access.redhat.com/security/cve/cve-2016-7065).");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40842/");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_red_hat_jboss_eap_server_detect.nasl");
  script_mandatory_keys("Redhat/JBoss/EAP/Installed");
  script_require_ports("Services/www", 443);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

#Variable initialize
jbossPort = "";
jbossVer = "";

if(!jbossPort = get_app_port(cpe:CPE)){
 exit(0);
}

## Get the version
if(!jbossVer = get_app_version(cpe:CPE, port:jbossPort)){
 exit(0);
}

## Checking for vulnerable version
if(jbossVer =~ "^(4|5)")
{
  if(version_is_equal(version:jbossVer, test_version:"4.0")||
     version_is_equal(version:jbossVer, test_version:"5.0"))
  {
    report = report_fixed_ver( installed_version:jbossVer, fixed_version:"None Available");
    security_message(data:report, port:jbossPort);
    exit(0);
  }
}
