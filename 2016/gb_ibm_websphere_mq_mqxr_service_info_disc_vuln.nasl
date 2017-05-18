###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mq_mqxr_service_info_disc_vuln.nasl 5732 2017-03-27 09:00:59Z teissa $
#
# IBM WebSphere MQ 'MQXR Service' Information Disclosure Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:ibm:websphere_mq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808652");
  script_version("$Revision: 5732 $");
  script_cve_id("CVE-2015-2012");
  script_bugtraq_id(82992);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-27 11:00:59 +0200 (Mon, 27 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-08-16 12:32:21 +0530 (Tue, 16 Aug 2016)");
  script_name("IBM WebSphere MQ 'MQXR Service' Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is installed with IBM WebSphere MQ
  and is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to the passphrase used to access
  the keystore is written to the file system in clear text in a properties file that
  is world readable.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users
  to obtain sensitive information.

  Impact Level: Application");

  script_tag(name:"affected", value:"IBM WebSphere MQ version 7.1 before 7.1.0.7,
  7.5 through 7.5.0.5, and 8.0 before 8.0.0.4.");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere MQ version 7.1.0.7,
  or 7.5.0.6, or 8.0.0.4, or later. For updates refer to,
  http://www-03.ibm.com/software/products/en/ibm-mq");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21968399");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ibm_websphere_mq_detect.nasl");
  script_mandatory_keys("IBM/Websphere/MQ/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
mqVer = "";

## Get version
if(!mqVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:mqVer, test_version:"8.0", test_version2:"8.0.0.3"))
{
  fix = "8.0.0.4";
  VULN = TRUE;
}

else if(version_in_range(version:mqVer, test_version:"7.5", test_version2:"7.5.0.5"))
{
  fix = "7.5.0.6";
  VULN = TRUE;
}

else if(version_in_range(version:mqVer, test_version:"7.1", test_version2:"7.1.0.6"))
{
  fix = "7.1.0.7";
  VULN = TRUE;
}
 
if(VULN)
{  
  report = report_fixed_ver(installed_version:mqVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
