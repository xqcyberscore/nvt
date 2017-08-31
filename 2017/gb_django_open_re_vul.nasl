###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_django_open_re_vul.nasl 6539 2017-07-05 12:02:14Z cfischer $
#
# Django django.views.static.serve Function Open Redirection Vulnerability
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

CPE = "cpe:/a:django_project:django";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107142");
  script_version("$Revision: 6539 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-05 14:02:14 +0200 (Wed, 05 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-04-07 16:31:00 +0200 (Fri, 07 Apr 2017)");
  script_cve_id("CVE-2017-7234");

  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Django django.views.static.serve Function Open Redirection Vulnerability");
  script_tag(name: "summary", value: "Django is prone to an open-redirection vulnerability because it fails to properly sanitize user-supplied input.");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Django is prone to an open-redirection vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name: "impact" , value: "An attacker can leverage this issue by constructing a crafted URI and enticing a user to follow it. When an unsuspecting victim follows the link, they may be redirected to an attacker-controlled site; this may aid in phishing attacks. Other attacks are possible.");

  script_tag(name: "affected", value: "Versions prior to Django 1.10.7, 1.9.13, and 1.8.18 are vulnerable");

  script_tag(name: "solution", value: "Updates are available. Please see the references or vendor advisory for more information.");

  script_xref(name: "URL" , value: "http://www.securityfocus.com/bid/97401");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("General");

  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  exit(0);

}

include("version_func.inc");
include("host_details.inc");

Ver = get_app_version(cpe: CPE);

if(!Ver ){
  exit(0);
}

if (Ver =~ "^1\.10\.")
{
    if(version_is_less(version: Ver, test_version:"1.10.7"))
    {
        fix = "1.10.7";
        VULN = TRUE;
    }
}

if (Ver =~ "^1\.9\.")
{
    if(version_is_less(version: Ver, test_version:"1.9.13"))
    {
        fix = "1.9.13";
        VULN = TRUE;
    }
}

if (Ver =~ "1\.8\.")
{
     if(version_is_less(version: Ver, test_version:"1.8.18"))
        {
            fix = "1.8.18";
            VULN = TRUE;
        }
}

if (VULN)
{
    report =  report_fixed_ver(installed_version:Ver, fixed_version: fix);
    security_message(data:report);
    exit(0);
}

