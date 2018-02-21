###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_mim_security_bypass_vuln.nasl 8882 2018-02-20 10:35:37Z cfischer $
#
# Samba Man in the Middle Security Bypass Vulnerability (Heimdal)
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811522");
  script_version("$Revision: 8882 $");
  script_cve_id("CVE-2017-11103");
  script_bugtraq_id(99551);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-02-20 11:35:37 +0100 (Tue, 20 Feb 2018) $");
  script_tag(name:"creation_date", value:"2017-07-13 12:28:31 +0530 (Thu, 13 Jul 2017)");
  script_name("Samba Man in the Middle Security Bypass Vulnerability (Heimdal)");

  script_tag(name:"summary", value:"This host is running Samba and is prone
  to a MITM authentication validation bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to error in function
  '_krb5_extract_ticket' where the KDC-REP service name must be obtained from
  encrypted version stored in 'enc_part' instead of the unencrypted version
  stored in 'ticket'. Use of the unecrypted version provides an opportunity
  for successful server impersonation and other attacks.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow
  a MITM attacker to impersonate a trusted server and thus gain elevated access
  to the domain by returning malicious replication or authorization data.

  Impact Level: Application");

  script_tag(name:"affected", value:"All versions of Samba from 4.0.0 before
  4.6.6 or 4.5.12 or 4.4.15.
  Note: All versions of Samba from 4.0.0 onwards using embedded Heimdal Kerberos.
  Samba binaries built against MIT Kerberos are not vulnerable.");

  script_tag(name:"solution", value:"Upgrade to Samba 4.6.6 or 4.5.12 or 4.4.15
  or later or apply the patch from https://www.samba.org/samba/security. 
  For updates refer to https://www.samba.org ");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "https://www.samba.org/samba/security/CVE-2017-11103.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sambaPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!sambaVer = get_app_version(cpe:CPE, port:sambaPort)){
  exit(0);
}

if(sambaVer =~ "^4\.")
{
  if(version_is_less(version:sambaVer, test_version:"4.4.15")){
    fix = "4.4.15";
  }

  else if(sambaVer =~ "^(4\.5)" && version_is_less(version:sambaVer, test_version:"4.5.12")){
    fix = "4.5.12";
  }

  else if(sambaVer =~ "^(4\.6)" && version_is_less(version:sambaVer, test_version:"4.6.6")){
    fix = "4.6.6";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:sambaVer, fixed_version:fix);
  security_message( data:report, port:sambaPort);
  exit(0);
}
exit(0);
