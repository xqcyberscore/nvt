###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_mult_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# OpenSSL Multiple Vulnerabilities (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

CPE = "cpe:/a:openssl:openssl";

tag_impact = "Successful exploitation will let the attacker cause memory access violation,
  security bypass or can cause denial of service.";

tag_affected = "OpenSSL version prior to 0.9.8k on all running platform.";

tag_insight = "- error exists in the 'ASN1_STRING_print_ex()' function when printing
    'BMPString' or 'UniversalString' strings which causes invalid memory
    access violation.

  - 'CMS_verify' function incorrectly handles an error condition when
    processing malformed signed attributes.

  - error when processing malformed 'ASN1' structures which causes invalid
    memory access violation.";

tag_solution = "Upgrade to OpenSSL version 0.9.8k
  http://openssl.org";

tag_summary = "This host is installed with OpenSSL and is prone to Multiple
  Vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800258");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0590", "CVE-2009-0591", "CVE-2009-0789");
  script_bugtraq_id(34256);
  script_name("OpenSSL Multiple Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34411");
  script_xref(name : "URL" , value : "http://www.openssl.org/news/secadv_20090325.txt");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Mar/1021905.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_detect_win.nasl");
  script_mandatory_keys("OpenSSL/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

# Grep for OpenSSL version prior to 0.9.8k
if( version_is_less( version:vers, test_version:"0.9.8k" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.9.8k", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );