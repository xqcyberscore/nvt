###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_4b3873b325_php-PHPMailer_fc27.nasl 7911 2017-11-27 04:54:41Z santu $
#
# Fedora Update for php-PHPMailer FEDORA-2017-4b3873b325
#
# Authors:
# System Generated Check
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.873749");
  script_version("$Revision: 7911 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-27 05:54:41 +0100 (Mon, 27 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-23 08:13:19 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for php-PHPMailer FEDORA-2017-4b3873b325");
  script_tag(name: "summary", value: "Check the version of php-PHPMailer");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Full Featured Email Transfer Class for 
PHP. PHPMailer features:

    * Supports emails digitally signed with S/MIME encryption!
    * Supports emails with multiple TOs, CCs, BCCs and REPLY-TOs
    * Works on any platform.
    * Supports Text &amp  HTML emails.
    * Embedded image support.
    * Multipart/alternative emails for mail clients that do not read
      HTML email.
    * Flexible debugging.
    * Custom mail headers.
    * Redundant SMTP servers.
    * Support for 8bit, base64, binary, and quoted-printable encoding.
    * Word wrap.
    * Multiple fs, string, and binary attachments (those from database,
      string, etc).
    * SMTP authentication.
    * Tested on multiple SMTP servers: Sendmail, qmail, Postfix, Gmail,
      Imail, Exchange, etc.
    * Good documentation, many examples included in download.
    * It&#39 s swift, small, and simple.
");
  script_tag(name: "affected", value: "php-PHPMailer on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-4b3873b325");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PJ56RXWJ42PXFZPVRGEDSP4HAE3TNRV6");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"php-PHPMailer", rpm:"php-PHPMailer~5.2.26~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
