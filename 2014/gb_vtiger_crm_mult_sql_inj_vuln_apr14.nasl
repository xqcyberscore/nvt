###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtiger_crm_mult_sql_inj_vuln_apr14.nasl 11878 2018-10-12 12:40:08Z cfischer $
#
# Vtiger CRM Multiple SQL Injection Vulnerabilities April-14
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:vtiger:vtiger_crm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804542");
  script_version("$Revision: 11878 $");
  script_cve_id("CVE-2013-3213");
  script_bugtraq_id(61563);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 14:40:08 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-17 18:28:20 +0530 (Thu, 17 Apr 2014)");
  script_name("Vtiger CRM Multiple SQL Injection Vulnerabilities April-14");


  script_tag(name:"summary", value:"This host is installed with Vtiger CRM and is prone to multiple
sql injection vulnerabilities");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it responds with error
message.");
  script_tag(name:"insight", value:"Multiple flaws are due to an,

  - Input passed via multiple parameters to various SOAP methods is not properly
  sanitised before being used in a SQL query.

  - Error within the 'validateSession()' function and multiple unspecified
  errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code, bypass certain security restrictions, manipulate certain data,
and compromise a vulnerable system.");
  script_tag(name:"affected", value:"Vtiger CRM version 5.0.0 through 5.4.0");
  script_tag(name:"solution", value:"Apply the patch Ignore this warning, if above mentioned patch is manually applied.
*****");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54336");
  script_xref(name:"URL", value:"https://www.vtiger.com/blogs/?p=1467");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27279");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_mandatory_keys("vtiger/installed");
  script_require_ports("Services/www", 80, 8888);
  script_xref(name:"URL", value:"https://www.vtiger.com/products/crm/540/VtigerCRM540_Security_Patch.zip

*****
NOTE:");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE,  port:http_port)){
  exit(0);
}

if(!vtVer = get_app_version(cpe:CPE,  port:http_port)){
  exit(0);
}

if(version_in_range(version:vtVer, test_version:"5.0.0", test_version2:"5.4.0"))
{
  security_message(port:http_port);
  exit(0);
}
