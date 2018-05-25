###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_composr_cms_css_vuln.nasl 9951 2018-05-24 13:51:37Z cfischer $
#
# Composr CMS v10.0.0 - Cross-Site Scripting Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:composr:cms';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107215");
  script_version("$Revision: 9951 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-24 15:51:37 +0200 (Thu, 24 May 2018) $");
  script_tag(name:"creation_date", value:"2017-06-13 11:59:56 +0200 (Tue, 13 Jun 2017)");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Composr CMS v10.0.0 - Cross-Site Scripting Vulnerability");

  script_tag(name: "summary", value: "This host is installed with Composr CMS and is prone to a Cross-Site Scripting vulnerability.");

  script_tag(name: "vuldetect", value: "Get the installed version with the help of the detection NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "The vulnerability is located in the 'Error Exception' of the 'Delete File' function. The remote attacker is
  able to inject own malicious code via GET method request in the 'file' parameter to provoke an execution. The injection point is the 'file'
  parameter and the execution point occurs in the error exception that displays the content to confirm a delete.");

  script_tag(name: "impact" , value: "Successful exploitation of the vulnerability results in session hijacking, non-persistent phishing attacks, non-persistent external redirects to
  malicious sources and non-persistent manipulation of affected or connected application modules.");

  script_tag(name: "affected", value: "Composr CMS version 10.0.0.");

  script_tag(name: "solution", value: "No known solution is available as of 24th May, 2018. Information regarding this issue will be updated once
  solution details are available. For updates refer to https://compo.sr/start.htm");

  script_xref(name: "URL" , value: "http://seclists.org/fulldisclosure/2017/Jun/15");
  script_tag(name:"solution_type", value:"NoneAvailable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("gb_composr_cms_detect.nasl");
  script_mandatory_keys("composr_cms/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe: CPE))
  exit(0);

if(!Ver = get_app_version(cpe: CPE, port: Port))
  exit(0);

if(version_is_equal(version: Ver, test_version: "10.0.0"))
{
  report =  report_fixed_ver(installed_version: Ver, fixed_version: "None Available");
  security_message(data: report, port: Port);
  exit(0);
}

exit(99);
