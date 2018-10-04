###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_6ed251c42b_spamassassin_fc27.nasl 11734 2018-10-03 11:48:15Z santu $
#
# Fedora Update for spamassassin FEDORA-2018-6ed251c42b
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.875123");
  script_version("$Revision: 11734 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-03 13:48:15 +0200 (Wed, 03 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-03 17:02:14 +0530 (Wed, 03 Oct 2018)");
  script_cve_id("CVE-2017-15705", "CVE-2018-11780", "CVE-2018-11781", "CVE-2016-1238");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for spamassassin FEDORA-2018-6ed251c42b");
  script_tag(name:"summary", value:"Check the version of spamassassin");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"SpamAssassin provides you with a way to
  reduce if not completely eliminate Unsolicited Commercial Email (SPAM) from
  your incoming email.  It can be invoked by a MDA such as sendmail or postfix,
  or can be called from a procmail script, .forward file, etc. It uses a
  genetic-algorithm evolved scoring system to identify messages which look
  spammy, then adds headers to the message so they can be filtered by the
  user&#39 s mail reading software.  This distribution includes the spamd/spamc
  components which create a server that considerably speeds processing of mail.

To enable spamassassin, if you are receiving mail locally, simply add
this line to your ~/.procmailrc:
INCLUDERC=/etc/mail/spamassassin/spamassassin-default.rc

To filter spam for all users, add that line to /etc/procmailrc
(creating if necessary).
");
  script_tag(name:"affected", value:"spamassassin on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-6ed251c42b");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/55XPURT3OKQTUXSX64QMYYM64TMNNMBB");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.2~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
