###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_d257909403_drupal7-backup_migrate_fc28.nasl 10443 2018-07-06 12:04:26Z santu $
#
# Fedora Update for drupal7-backup_migrate FEDORA-2018-d257909403
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
  script_oid("1.3.6.1.4.1.25623.1.0.874767");
  script_version("$Revision: 10443 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-06 14:04:26 +0200 (Fri, 06 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-05 06:12:31 +0200 (Thu, 05 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for drupal7-backup_migrate FEDORA-2018-d257909403");
  script_tag(name:"summary", value:"Check the version of drupal7-backup_migrate");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"Back up and restore your Drupal MySQL database, 
code, and files or migrate a site between environments. Backup and Migrate supports 
gzip, bzip and zip compression as well as automatic scheduled backups.

With Backup and Migrate you can dump some or all of your database tables to a
file download or save to a file on the server or offsite, and to restore from
an uploaded or previously saved database dump. You can choose which tables and
what data to backup and cache data is excluded by default.

Features:
* Backup/Restore multiple MySQL databases and code
* Backup of files directory is built into this version
* Add a note to backup files
* Smart delete options make it easier to manage backup files
* Backup to FTP/S3/Email or 'http://NodeSquirrel.com'
* Drush integration
* Multiple backup schedules
* AES encryption for backups

This package provides the following Drupal module:
* backup_migrate
");
  script_tag(name:"affected", value:"drupal7-backup_migrate on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-d257909403");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YHICFXLXS3IG7R4RAA2BY2OG5VLLXJV5");
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

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"drupal7-backup_migrate", rpm:"drupal7-backup_migrate~3.5~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
