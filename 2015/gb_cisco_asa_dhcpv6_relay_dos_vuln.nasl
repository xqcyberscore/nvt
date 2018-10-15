###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_dhcpv6_relay_dos_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Cisco ASA Software DHCPv6 Relay Denial of Service Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:cisco:asa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806529");
  script_version("$Revision: 11872 $");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2015-0578");
  script_bugtraq_id(72718);
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 12:27:12 +0530 (Fri, 20 Nov 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("Cisco ASA Software DHCPv6 Relay Denial of Service Vulnerability");

  script_tag(name:"summary", value:"This host is running Cisco ASA Software and
  is prone to denial of service vulnerability.
  This NVT has been replaced by NVT gb_cisco_asa_CSCur45455.nasl
   (OID:1.3.6.1.4.1.25623.1.0.106053).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation
  of crafted DHCP packets. Cisco ASA Software is affected by this vulnerability
  only when configured as a DHCP version 6 relay.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated, remote attacker to cause an affected device to reload,
  resulting in a denial of service condition.");

  script_tag(name:"affected", value:"Cisco ASA Software versions 7.2 before
  8.2(5.58), 8.3 before 8.4(7.29), 8.5 before 9.0(4.37), 8.7 before 8.7(1.17),
  9.0 before 9.0(4.37), 9.1 before 9.1(6.8), 9.2 before 9.2(4), 9.3 before
  9.3(3.5), 9.4 before 9.4(2).");

  script_tag(name:"solution", value:"Upgrade to 8.2(5.58) or 8.4(7.29) or
  9.0(4.37) or 8.7(1.17) or 9.0(4.37) or 9.1(6.8) or 9.2(4) or 9.3(3.5) or
  9.4(2) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031542");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=37022");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150115-asa-dhcp");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl");
  script_mandatory_keys("cisco_asa/version");
  script_xref(name:"URL", value:"http://www.cisco.com");
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in
## gb_cisco_asa_CSCur45455.nasl(1.3.6.1.4.1.25623.1.0.106053).

include("version_func.inc");
include("host_details.inc");

if(!cisVer = get_app_version(cpe:CPE)){
  exit(0);
}

cisVer = ereg_replace(string:cisVer, pattern:"\(([0-9.]+)\)", replace:".\1");

if(cisVer =~ "^(7|8|9)\.")
{
  if(version_in_range(version:cisVer, test_version:"7.2", test_version2:"8.2.5.57"))
  {
    fix = "8.2(5.58)";
    VULN = TRUE;
  }

  else if(version_in_range(version:cisVer, test_version:"8.3", test_version2:"8.4.7.28"))
  {
    fix = "8.4(7.29)";
    VULN = TRUE;
  }

  else if(version_in_range(version:cisVer, test_version:"8.5", test_version2:"9.0.4.36"))
  {
    fix = "9.0(4.37)";
    VULN = TRUE;
  }

  else if(version_in_range(version:cisVer, test_version:"9.1", test_version2:"9.1.6.7"))
  {
    fix = "9.1(6.8)";
    VULN = TRUE;
  }

  else if(version_in_range(version:cisVer, test_version:"9.2", test_version2:"9.2.3"))
  {
    fix = "9.2(4)";
    VULN = TRUE;
  }

  else if(version_in_range(version:cisVer, test_version:"9.3", test_version2:"9.3.3.4"))
  {
    fix = "9.3(3.5)";
    VULN = TRUE;
  }

  else if(version_in_range(version:cisVer, test_version:"9.4", test_version2:"9.4.1"))
  {
    fix = "9.4(2)";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = 'Installed version: ' + cisVer + '\n' +
             'Fixed version:     ' + fix + '\n';
    security_message(data:report);
    exit(0);
  }
}
