###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Tools kASLR Protection Bypass Vulnerability (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:vmware:tools";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810267");
  script_version("2019-07-05T09:29:25+0000");
  script_cve_id("CVE-2016-5328");
  script_bugtraq_id(93886);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-05 09:29:25 +0000 (Fri, 05 Jul 2019)");
  script_tag(name:"creation_date", value:"2017-01-10 12:53:05 +0530 (Tue, 10 Jan 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VMware Tools kASLR Protection Bypass Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with VMware Tools
  and is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified security
  bypass error when System Integrity Protection (SIP) is enabled.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  privileged users to obtain kernel memory addresses to bypass the kASLR
  protection mechanism.");

  script_tag(name:"affected", value:"VMware Tools 9.x and 10.x before 10.1.0
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to VMware Tool version 10.1.0 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0017.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_tools_detect_macosx.nasl");
  script_mandatory_keys("VMwareTools/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vmtoolVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmtoolVer =~ "^(9|10)")
{
  if(version_is_less(version:vmtoolVer, test_version:"10.1.0"))
  {
    report = report_fixed_ver(installed_version:vmtoolVer, fixed_version:"10.1.0");
    security_message(data:report);
    exit(0);
  }
}
