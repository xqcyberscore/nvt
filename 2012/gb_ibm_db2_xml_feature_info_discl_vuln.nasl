###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_xml_feature_info_discl_vuln.nasl 10005 2018-05-29 13:54:41Z cfischer $
#
# IBM DB2 XML Feature Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802457");
  script_version("$Revision: 10005 $");
  script_cve_id("CVE-2012-0713");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-05-29 15:54:41 +0200 (Tue, 29 May 2018) $");
  script_tag(name:"creation_date", value:"2012-09-06 17:13:55 +0530 (Thu, 06 Sep 2012)");
  script_name("IBM DB2 XML Feature Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73520");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/428862.php");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21592556");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC81462");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_mandatory_keys("IBM-DB2/Remote/ver", "IBM-DB2/installed");

  script_tag(name : "impact" , value : "Successful exploitation allows remote users to read arbitrary
  XML files.

  Impact Level: Application");
  script_tag(name : "affected" , value : "IBM DB2 version 9.7 before FP6");
  script_tag(name : "insight" , value : "The flaw is caused due an error in the XML feature, which can be exploited
  to read arbitrary XML files via unknown vectors.");
  script_tag(name : "solution" , value : "Upgrade to IBM DB2 version 9.7 FP6 or later,

  For updates refer to http://www-01.ibm.com/support/docview.wss?uid=swg27007053");
  script_tag(name : "summary" , value : "The host is running IBM DB2 and is prone to information disclosure
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ibmVer = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(ibmVer =~ "^0907\.*")
{
  # IBM DB2 9.7 FP 5 => 09076
  if(version_is_less(version:ibmVer, test_version:"09076"))
  {
    security_message(port:port);
    exit(0);
  }
}
