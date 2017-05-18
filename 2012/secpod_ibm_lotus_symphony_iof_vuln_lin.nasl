###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_lotus_symphony_iof_vuln_lin.nasl 6018 2017-04-24 09:02:24Z teissa $
#
# IBM Lotus Symphony Image Object Integer Overflow Vulnerability (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902809");
  script_version("$Revision: 6018 $");
  script_cve_id("CVE-2012-0192");
  script_bugtraq_id(51591);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-24 11:02:24 +0200 (Mon, 24 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-01-25 12:12:12 +0530 (Wed, 25 Jan 2012)");
  script_name("IBM Lotus Symphony Image Object Integer Overflow Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_ibm_lotus_symphony_detect_lin.nasl");
  script_mandatory_keys("IBM/Lotus/Symphony/Lin/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47245");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51591");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72424");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21578684");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code in
  the context of affected applications. Failed exploit attempts will likely
  result in denial-of-service conditions.

  Impact Level: Application");
  script_tag(name:"affected", value:"IBM Lotus Symphony versions 3.0.0 FP3 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an integer overflow error when processing embedded
  image objects. This can be exploited to cause a heap-based buffer overflow
  via a specially crafted JPEG object within a DOC file.");
  script_tag(name:"solution", value:"Upgrade to IBM Lotus Symphony version 3.0.1 or later,
  For updates refer to http://www.ibm.com/software/lotus/symphony/home.nsf/home");
  script_tag(name:"summary", value:"This host is installed with IBM Lotus Symphony and is prone to
  integer overflow vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

## Get version from KB
version = get_kb_item("IBM/Lotus/Symphony/Lin/Ver");

## Check for IBM Lotus Symphony Versions 3.0.0 FP3 and prior
if(version_is_less_equal(version:version, test_version:"3.0.0.FP3")){
  report = report_fixed_ver(installed_version:version, fixed_version:"3.0.1");
  security_message(data:report);
  exit(0);
}

exit(99);
