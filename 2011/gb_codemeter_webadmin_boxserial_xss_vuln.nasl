###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_codemeter_webadmin_boxserial_xss_vuln.nasl 4920 2017-01-02 15:37:20Z cfi $
#
# CodeMeter WebAdmin 'Licenses.html' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = 'cpe:/a:wibu:codemeter_webadmin';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801989");
  script_version("$Revision: 4920 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 16:37:20 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_cve_id("CVE-2011-3689");
  script_bugtraq_id(48082);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CodeMeter WebAdmin 'Licenses.html' Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH,");
  script_family("Web application abuses");
  script_dependencies("gb_codemeter_webadmin_detect.nasl");
  script_mandatory_keys("CodeMeter_WebAdmin/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44800/");
  script_xref(name:"URL", value:"http://forums.cnet.com/7726-6132_102-5144590.html");
  script_xref(name:"URL", value:"http://www.solutionary.com/index/SERT/Vuln-Disclosures/CodeMeter-WebAdmin.html");

  tag_impact = "Successful exploitation will allow attackers to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the
  affected site.

  Impact Level: Application";

  tag_affected = "CodeMeter WebAdmin version 4.30 and 3.30";

  tag_insight = "The flaw is due to an input passed via the 'BoxSerial' parameter
  to the 'Licenses.html' script is not properly sanitised before being returned
  to the user.";

  tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.";

  tag_summary = "The host is running CodeMeter WebAdmin and is prone to
  cross-site scripting vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

## Check for version before 4.30 and 3.30
if( version_is_equal( version:vers, test_version:"4.30" ) ||
    version_is_equal( version:vers, test_version:"3.30" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"Unknown" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
