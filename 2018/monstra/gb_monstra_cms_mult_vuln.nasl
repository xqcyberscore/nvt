###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_monstra_cms_mult_vuln.nasl 14102 2019-03-12 03:29:04Z ckuersteiner $
#
# Monstra CMS <= 3.0.4 Multiple Vulnerabilities
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113204");
  script_version("2019-07-08T11:25:53+0000");
  script_tag(name:"last_modification", value:"2019-07-08 11:25:53 +0000 (Mon, 08 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-05-29 16:04:31 +0200 (Tue, 29 May 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2018-11472", "CVE-2018-11473", "CVE-2018-11474", "CVE-2018-11475",
                "CVE-2018-18048", "CVE-2018-6383", "CVE-2018-6550", "CVE-2018-9037",
                "CVE-2018-9038", "CVE-2018-10109", "CVE-2018-10118", "CVE-2018-10121",
                "CVE-2018-11678", "CVE-2018-17418", "CVE-2018-14922", "CVE-2018-16608",
                "CVE-2018-15886", "CVE-2018-17026", "CVE-2018-17024", "CVE-2018-17025",
                "CVE-2018-16979", "CVE-2018-16977", "CVE-2018-16978", "CVE-2018-16819",
                "CVE-2018-18694", "CVE-2018-16820", "CVE-2018-11227");

  script_name("Monstra CMS <= 3.0.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_monstra_cms_detect.nasl");
  script_mandatory_keys("monstra_cms/detected");

  script_tag(name:"summary", value:"Monstra CMS is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - Reflected XSS during Login (i.e., the login parameter to admin/index.php)

  - XSS in the registration Form (i.e., the login parameter to users/registration)

  - A password change at admin/index.php?id=users&action=edit&user_id=1 does not invalidate a session that is open in a different browser

  - A password change at users/1/edit does not invalidate a session that is open in a different browser

  - Monstra CMS allows users to upload arbitrary files, which leads to remote command execution on the server,
    for example because .php (lowercase) is blocked but .PHP (uppercase) is not

  - Monstra CMS through 3.0.4 has an incomplete 'forbidden types' list that excludes .php (and similar) file extensions
    but not the .pht or .phar extension, which allows remote authenticated admins to execute arbitrary PHP code by uploading a file

  - XSS in the title function in plugins/box/pages/pages.plugin.php via a page title to admin/index.php

  - Remote Code Execution via an upload_file request for a .zip file, which is automatically extracted and may contain .php files.

  - Monstra CMS 3.0.4 allows remote attackers to delete files via an admin/index.php?id=filesmanager&delete_dir=./&path=uploads/ request

  - Stored XSS vulnerability when an attacker has access to the editor role,
    and enters the payload in the content section of a new page in the blog catalog.

  - Stored XSS via the Name field on the Create New Page screen under the admin/index.php?id=pages URI,
    related to plugins/box/pages/pages.admin.php.

  - plugins/box/pages/pages.admin.php has a stored XSS vulnerability when an attacker has access to the editor role,
    and enters the payload in the title section of an admin/index.php?id.pages&action.edit_page&name.error404 (aka Edit 404 page) action.

  - plugins/box/users/users.plugin.php allows Login Rate Limiting Bypass via manipulation of the login_attempts cookie.

  - Multiple cross-site scripting (XSS) vulnerabilities allow remote attackers to inject arbitrary web script or HTML via the
    (1) first name or (2) last name field in the edit profile page.

  - An attacker with 'Editor' privileges can change the password of the administrator via an Insecure Direct Object Reference (IDOR)
    in admin/index.php?id=users&action=edit&user_id=1.

  - Monstra does not properly restrict modified Snippet content, as demonstrated by the
    admin/index.php?id=snippets&action=edit_snippet&filename=google-analytics URI,
    which allows attackers to execute arbitrary PHP code by placing this code after a <?php substring.

  - The admin/index.php page allows XSS via the page_meta_title parameter in an edit_page&name=error404 action.

  - The admin/index.php page allows XSS via the page_meta_title parameter in an add_page action.

  - The admin/index.php page allows XSS via the page_meta_title parameter in an edit_page action for a page with no special role.

  - There is a HTTP header injection in the plugins/captcha/crypt/cryptographp.php cfg parameter.

  - There is an information leakage risk (e.g., PATH, DOCUMENT_ROOT, and SERVER_ADMIN)
    in libraries/Gelato/ErrorHandler/Resources/Views/Errors/exception.php.

  - There is an XSS when one tries to register an account with a crafted password parameter to users/registration.

  - The admin/index.php page allows arbitrary file deletion via id=filesmanager&path=uploads/.......//./.......//./&delete_file= requests.

  - The admin/index.php?id=filesmanager page allows remote authenticated administrators to trigger stored XSS via
    JavaScript content in a file whose name lacks an extension. Such a file is interpreted as text/html in certain cases.

  - The admin/index.php page allows arbitrary directory listing via id=filesmanager&path=uploads/.......//./.......//./ requests.

  - XSS via index.php.");
  script_tag(name:"affected", value:"Monstra CMS through version 3.0.4.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.

  Note: Monstra CMS is deprecated / not supported anymore by the vendor.");

  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/443");
  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/444");
  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/445");
  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/446");

  exit(0);
}

CPE = "cpe:/a:monstra:monstra";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "3.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
