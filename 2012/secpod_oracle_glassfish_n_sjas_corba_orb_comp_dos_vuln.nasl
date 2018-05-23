###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_glassfish_n_sjas_corba_orb_comp_dos_vuln.nasl 9927 2018-05-23 04:13:59Z ckuersteiner $
#
# Oracle GlassFish/Java System Application Server CORBA ORB Subcomponent DoS Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903044");
  script_version("$Revision: 9927 $");
  script_cve_id("CVE-2012-3155");
  script_bugtraq_id(56073);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-05-23 06:13:59 +0200 (Wed, 23 May 2018) $");
  script_tag(name:"creation_date", value:"2012-10-25 16:57:46 +0530 (Thu, 25 Oct 2012)");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("Oracle GlassFish/Java System Application Server CORBA ORB Subcomponent DoS Vulnerability");

  script_xref(name: "URL", value: "http://secunia.com/advisories/51017/");
  script_xref(name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_dependencies("GlassFish_detect.nasl", "secpod_sun_java_app_serv_detect.nasl");
  script_require_ports("Services/www", 8080);

  script_tag(name: "impact", value: "Successful exploitation could allow malicious attackers to cause a denial of
service.");

  script_tag(name: "affected", value: "Oracle GlassFish version 2.1.1, 3.0.1 and 3.1.2, Oracle Java System
Application Server version 8.1 and 8.2");

  script_tag(name: "insight", value: "The flaw is caused due to an unspecified error within the CORBA ORB
subcomponent, which allows remote users to cause a denial of service condition.");

  script_tag(name: "summary", value: "This host is running Oracle GlassFish/Java System Application Server and is
prone to denial of service vulnerability.");

  script_tag(name: "solution", value: "Apply the security updates.
http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = 'cpe:/a:oracle:glassfish_server';

if (port = get_app_port(cpe: CPE)) {
  if (!version = get_app_version(cpe: CPE, port: port))
    exit(0);

  if (version_is_equal(version: version, test_version:"3.0.1")||
      version_is_equal(version: version, test_version:"3.1.2")||
      version_is_equal(version: version, test_version:"2.1.1")) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

CPE = 'cpe:/a:sun:java_system_application_server';

if (port = get_app_port(cpe: CPE)) {
  if (!version = get_app_version(cpe: CPE, port: port))
    exit(0);

  version = ereg_replace(pattern:"_", replace:".", string:version);

  if (version_is_equal(version:version, test_version:"8.1") ||
     version_is_equal(version:version, test_version:"8.2")){
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

exit(0);
