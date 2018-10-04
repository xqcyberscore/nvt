###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_phantompdf_rce_n_info_disc_vuln_win.nasl 11741 2018-10-04 08:03:44Z santu $
#
# Foxit PhantomPDF Remote Code Execution And Information Disclosure Vulnerabilities - Oct18 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814066");
  script_version("$Revision: 11741 $");
  script_cve_id("CVE-2018-17607", "CVE-2018-17608", "CVE-2018-17609", "CVE-2018-17610",
                "CVE-2018-17611", "CVE-2018-17781");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-04 10:03:44 +0200 (Thu, 04 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-03 11:59:56 +0530 (Wed, 03 Oct 2018)");
  script_name("Foxit PhantomPDF Remote Code Execution And Information Disclosure Vulnerabilities - Oct18 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Foxit PhantomPDF
  and is prone to code execution and information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - The creation of ArrayBuffer and DataView objects is mishandled.

  - The properties of Annotation objects are mishandled.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service (use-after-free)
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version before 9.3 on windows");

  script_tag(name:"solution", value:"Upgrade to Foxit PhantomPDF version 9.3 or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE);
pdfVer = infos['version'];
pdfPath = infos['location'];

if(version_is_less(version:pdfVer, test_version:"9.3"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"9.3", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}

exit(99);
