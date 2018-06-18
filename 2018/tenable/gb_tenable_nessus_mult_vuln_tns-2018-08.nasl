###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tenable_nessus_mult_vuln_tns-2018-08.nasl 10220 2018-06-15 12:17:34Z santu $
#
# Tenable Nessus Multiple Vulnerabilities(tns-2018-08)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813437");
  script_version("$Revision: 10220 $");
  script_cve_id("CVE-2017-11742", "CVE-2017-9233", "CVE-2016-9063", "CVE-2016-0718",
                "CVE-2016-5300", "CVE-2012-0876", "CVE-2016-4472", "CVE-2012-6702",
                "CVE-2018-11214", "CVE-2017-18258", "CVE-2017-16932", "CVE-2017-16931",
                "CVE-2017-9050", "CVE-2017-9049", "CVE-2017-9048", "CVE-2017-9047",
                "CVE-2017-8872", "CVE-2017-7375", "CVE-2017-5969", "CVE-2016-9318",
                "CVE-2016-5131", "CVE-2018-9251", "CVE-2017-1000061", "CVE-2012-6139",
                "CVE-2015-7995", "CVE-2015-9019", "CVE-2016-1683", "CVE-2016-1684",
                "CVE-2017-5029", "CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842",
                "CVE-2016-9843", "CVE-2014-8964", "CVE-2014-9769", "CVE-2015-2327",
                "CVE-2015-2328", "CVE-2015-3217", "CVE-2015-5073", "CVE-2015-8380",
                "CVE-2015-8381", "CVE-2015-8382", "CVE-2015-8383", "CVE-2015-8384",
                "CVE-2015-8385", "CVE-2015-8386", "CVE-2015-8387", "CVE-2015-8388",
                "CVE-2015-8389", "CVE-2015-8390", "CVE-2015-8391", "CVE-2015-8392",
                "CVE-2015-8394", "CVE-2015-8395", "CVE-2016-1283", "CVE-2016-3191",
                "CVE-2017-6004", "CVE-2017-7186", "CVE-2017-7244", "CVE-2017-7245",
                "CVE-2017-7246");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 14:17:34 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-15 11:03:08 +0530 (Fri, 15 Jun 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Tenable Nessus Multiple Vulnerabilities(tns-2018-08)");

  script_tag(name:"summary", value:"This host is running Nessus and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws exists as some of the third-party
  components used within Nessus to provide underlying functionality were found to
  contain various vulnerabilities. The components with vulnerabilities include
  expat, libjpeg, libXML2, libXMLSEC, libXSLT, Zlib and libPCRE");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers potentially to gain privileges, execute arbitrary code, bypass
  security restrictions, conduct denial-of-service, gain access to potentially
  sensitive information, conduct XML External Entity (XXE) attacks and unspecified
  other impacts.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Nessus versions prior to version 7.1.1");

  script_tag(name:"solution", value:"Upgrade to nessus version 7.1.1 or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://www.tenable.com");
  script_xref(name : "URL" , value : "https://www.tenable.com/security/tns-2018-08");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!nesPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:nesPort, exit_no_version:TRUE);
nesVer = infos['version'];
path = infos['location'];

if(version_is_less(version:nesVer, test_version:"7.1.1"))
{
  report = report_fixed_ver(installed_version:nesVer, fixed_version:"7.1.1", install_path:path);
  security_message(data:report, port:nesPort);
  exit(0);
}
exit(0);
