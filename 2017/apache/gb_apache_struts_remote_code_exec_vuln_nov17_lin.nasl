###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_remote_code_exec_vuln_nov17_lin.nasl 7900 2017-11-24 10:35:02Z asteins $
#
# Apache Struts 'TextParseUtil.translateVariables' RCE Vulnerability (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812065");
  script_version("$Revision: 7900 $");
  script_cve_id("CVE-2016-3090");
  script_bugtraq_id(85131);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-11-24 11:35:02 +0100 (Fri, 24 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-02 15:20:14 +0530 (Thu, 02 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Struts 'TextParseUtil.translateVariables' RCE Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  'TextParseUtil.translateVariables' method which does not filter malicious
  OGNL expressions.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the affected application. Failed
  exploit attempts may cause a denial-of-service condition.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache Struts Version 2.0.0 through 2.3.16.3
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to Apache Struts Version 2.3.24.1 or
  later. For updates refer to http://struts.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://cwiki.apache.org/confluence/display/WW/S2-027");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ApacheStruts/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

appVer = "";
appPort = "";

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!appVer = get_app_version(cpe:CPE, port:appPort)){
  exit(0);
}

if(appVer =~ "^(2\.)")
{
  if(version_in_range(version:appVer, test_version:"2.0.0", test_version2:"2.3.16.3"))
  {
    report = report_fixed_ver(installed_version:appVer, fixed_version:"2.3.24.1");
    security_message(data:report, port:appPort);
    exit(0);
  }
}
exit(0);
