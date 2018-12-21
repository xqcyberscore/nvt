###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_0f5e6e9957_php-phpmailer6_fc28.nasl 12851 2018-12-21 01:34:55Z ckuersteiner $
#
# Fedora Update for php-phpmailer6 FEDORA-2018-0f5e6e9957
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.875315");
  script_version("$Revision: 12851 $");
  script_cve_id("CVE-2018-19296");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 02:34:55 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-04 08:28:01 +0100 (Tue, 04 Dec 2018)");
  script_name("Fedora Update for php-phpmailer6 FEDORA-2018-0f5e6e9957");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");

  script_xref(name:"FEDORA", value:"2018-0f5e6e9957");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZXE5CR2VWTH7XFU3CHRXPFVHMGA7ZJX2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-phpmailer6'
  package(s) announced via the FEDORA-2018-0f5e6e9957 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PHPMailer - A full-featured email creation and transfer class for PHP

Class Features
* Probably the world&#39 s most popular code for sending email from PHP!
* Used by many open-source projects:
  WordPress, Drupal, 1CRM, SugarCRM, Yii, Joomla! and many more
* Integrated SMTP support - send without a local mail server
* Send emails with multiple To, CC, BCC and Reply-to addresses
* Multipart/alternative emails for mail clients that do not read HTML email
* Add attachments, including inline
* Support for UTF-8 content and 8bit, base64, binary, and quoted-printable
  encodings
* SMTP authentication with LOGIN, PLAIN, CRAM-MD5 and XOAUTH2 mechanisms
  over SSL and SMTP+STARTTLS transports
* Validates email addresses automatically
* Protect against header injection attacks
* Error messages in 47 languages!
* DKIM and S/MIME signing support
* Compatible with PHP 5.5 and later
* Namespaced to prevent name clashes
* Much more!


Autoloader: /usr/share/php/PHPMailer/PHPMailer6/autoload.php
");

  script_tag(name:"affected", value:"php-phpmailer6 on Fedora 28.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"php-phpmailer6", rpm:"php-phpmailer6~6.0.6~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
