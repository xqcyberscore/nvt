###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mq_dos_vuln_sep16.nasl 5745 2017-03-28 09:01:00Z teissa $
#
# IBM WebSphere MQ Denial of Service Vulnerability - September16
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809052");
  script_version("$Revision: 5745 $");
  script_cve_id("CVE-2016-0379");
  script_bugtraq_id(93146);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-28 11:01:00 +0200 (Tue, 28 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-09-29 18:00:59 +0530 (Thu, 29 Sep 2016)");
  script_name("IBM WebSphere MQ Denial of Service Vulnerability - September16");

  script_tag(name:"summary", value:"This host is installed with IBM WebSphere MQ
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to incorrect handling of 
  MQ protocol flow.");

  script_tag(name:"impact", value:"Successful exploitation will allow an 
  authenticated user with queue manager rights to cause a denial of service
  to channels.

  Impact Level: Application");

  script_tag(name:"affected", value:"IBM WebSphere MQ version 8.0.0.0 through 
  8.0.0.4 and 7.5.0.0 through 7.5.0.6.");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere MQ version 8.0.0.5
  or 7.5.0.7 or later. For updates refer to,
  http://www-03.ibm.com/software/products/en/ibm-mq");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21984565");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
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

if(version_in_range(version:mqVer, test_version:"8.0.0.0", test_version2:"8.0.0.4"))
{
  fix = "8.0.0.5";
  VULN = TRUE;
}
else if(version_in_range(version:mqVer, test_version:"7.5.0.0", test_version2:"7.5.0.6"))
{
  fix = "7.5.0.7";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:mqVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
