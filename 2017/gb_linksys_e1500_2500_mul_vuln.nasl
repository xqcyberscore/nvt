###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linksys_e1500_2500_mul_vuln.nasl 7638 2017-11-03 07:11:45Z cfischer $
#
# Linksys E1500/E2500 Multiple Vulnerabilities
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:linksys:devices";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107202");
  script_version("$Revision: 7638 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-03 08:11:45 +0100 (Fri, 03 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-02 11:57:11 +0530 (Thu, 02 Nov 2017)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Linksys E1500/E2500 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Linksys E1500 or E2500 device and is prone to multiple
vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of the detection NVT and check if the
version is vulnerable or not.");

  script_tag(name:"insight", value:"The vulnerability is caused by missing input validation in the ping_size
parameter and can be exploited to inject and execute arbitrary shell commands.");

  script_tag(name:"impact", value:"The attacker can start a telnetd or upload and execute a backdoor to
compromise the device.");

  script_tag(name:"affected", value:"Linksys E1500 v1.0.00 build 9, v1.0.04 build 2, v1.0.05 build 1 and
Linksys E2500 v1.0.03.");

  script_tag(name:"solution", value:"No solution or patch is available as of 02nd November, 2017. Information
regarding this issue will be updated once solution details are available. For details refer to http://www.linksys.com");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "http://www.s3cur1ty.de/m1adv2013-004");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_dependencies("gb_linksys_devices_detect.nasl");
  script_mandatory_keys("Linksys/model", "Linksys/firmware");
  script_require_ports("Services/www", 80, 8080);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

get_app_version(cpe: CPE, nofork: TRUE); # To have a reference to the Detection NVT.

if (!model = get_kb_item("Linksys/model")) exit(0);
if (!firmware = get_kb_item("Linksys/firmware")) exit(0);

if (model == "E1500")
{
    if (firmware == "1.0.00 build 4" || firmware == "1.0.04 build 2" || firmware == "1.0.05 build 1" )
    {
        VER = model + " firmware: " + firmware;
        VULN = TRUE;
    }
}
else if (model == "E2500")
{
    if (firmware == "1.0.03")
    {
        VER = model + " firmware: " + firmware;
        VULN = TRUE;
    }
}

if (VULN)
{
    report = report_fixed_ver(installed_version: VER, fixed_version: "NoneAvailable");
    security_message(data: report, port: 0);
    exit(0);
}

exit(0);
