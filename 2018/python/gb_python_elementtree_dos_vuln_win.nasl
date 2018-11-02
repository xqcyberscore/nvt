###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_python_elementtree_dos_vuln_win.nasl 12191 2018-11-01 15:41:33Z mmartin $
#
# Python Elementtree Denial of Service Vulnerability (Windows)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
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

CPE = 'cpe:/a:python:python';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814304");
  script_version("$Revision: 12191 $");
  script_cve_id("CVE-2018-14647");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-01 16:41:33 +0100 (Thu, 01 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-03 17:02:15 +0530 (Wed, 03 Oct 2018)");
  script_name("Python Elementtree Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Python and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists because Python's elementtree
  C accelerator fails to initialise Expat's hash salt during initialization");

  script_tag(name:"impact", value:"Successful exploitation allows denial of
  service attacks against Expat by constructing an XML document that would cause
  pathological hash collisions in Expat's internal data structures, consuming large
  amounts CPU and RAM.");

  script_tag(name:"affected", value:"Python versions 3.8, 3.7, 3.6, 3.5, 3.4 and 2.7 on Windows");

  script_tag(name:"solution", value:"No known solution is available as of
  01st November, 2018. Information regarding this issue will be updated once
  solution details are available. For updates refer to Reference links.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"NoneAvailable");
  script_xref(name:"URL", value:"https://bugs.python.org/issue34623");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-14647");
  script_xref(name:"URL", value:"https://www.python.org");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/105396/info");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("Python/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
pyVer = infos['version'];
pypath = infos['location'];

if(pyVer =~ "^(2.7|3.4|3.5|3.6|3.7|3.8)")
{
  report = report_fixed_ver(installed_version:pyVer, fixed_version:"None available", install_path: pypath);
  security_message(data:report);
  exit(0);
}
exit(0);
