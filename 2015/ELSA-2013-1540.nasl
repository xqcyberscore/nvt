# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1540.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
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
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.123532");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:05:09 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1540");
script_tag(name: "insight", value: "ELSA-2013-1540 -  evolution security, bug fix, and enhancement update - cheese [2.28.1-8] - Rebuild against newer evolution-data-server. Resolves: #973276 control-center [2.28.1-39] - Rebuild against newer evolution-data-server. Resolves: #973279 ekiga [3.2.6-4] - Rebuild against newer evolution-data-server. - Add patch to build break (include where needed) Resolves: #973281 evolution [2.32.3-30.el6] - Update patch for RH bug #975409 (Custom message in alarm notification) - Add patch for RH bug #1014743 (Use system timezone has no effect) - Add patch for RH bug #1014677 (Search filter persists when changing folders) [2.32.3-29.el6] - Add patch for RH bug #1013543 (Freeze during migration of pre-2.24 mails) [2.32.3-28.el6] - Add patch for RH bug #1012399 (Fails to display task mail attachment) - Bump evolution-data-server version requirement (for RH bug #1009426) [2.32.3-27.el6] - Add patch for RH bug #1009517 (Be aware of 'no-alarm-after-start' calendar capability) [2.32.3-26.el6] - Add patch for RH bug #1006764 (Plugin actions not updated) [2.32.3-25.el6] - Add patch for RH bug #1003578 (Update actions on search execute) [2.32.3-24.el6] - Update translations for the Exchange Web Services advertisement [2.32.3-23.el6] - Build evolution-devel-docs for noarch only [2.32.3-22.el6] - Add a devel-docs subpackage and do not ship evolution-settings (RH bug #1000323) [2.32.3-21.el6] - Remove bogofilter plugin from el6 (missed previous removal during rebase) [2.32.3-20.el6] - Update bn_IN translation [2.32.3-19.el6] - Show a one-time dialog on upgrade advertising Exchange Web Services. [2.32.3-18.el6] - Update translation patch [2.32.3-17.el6] - Add patch for icons in a message list Wide View [2.32.3-16.el6] - Add patch for translation updates [2.32.3-15.el6] - Update patch for RH bug #949610 (Avoid runtime warnings caused by async load) [2.32.3-14.el6] - Update patch for RH bug #975409 (Custom message in alarm notification) - Add patch for RH bug #985528 (Multiple contacts remove confuses view) [2.32.3-13.el6] - Obsolete evolution-conduits, thus an update can be done, when it's installed - Add patch for RH bug #981313 (a11y in the Contacts' minicard view) - Add patch for RH bug #981257 (Save changes in addressbook backend's ensure_sources) [2.32.3-12.el6] - Add patch for use-after-free memory in mail account editor found by valgrind [2.32.3-11.el6] - Add patch for RH bug #978525 (CamelSession left with unset network-available) [2.32.3-10.el6] - Add patch for RH bug #956510 (Alarm notify crash and other related fixes in alarm notify) - Update patch for RH bug #977292 (Close also evolution-alarm-notify process) [2.32.3-9.el6] - Add patch for RH bug #624851 (Select S/MIME encryption certificate) - Add patch for RH bug #628174 (Copy/Paste text in calendar views) - Add patch for RH bug #971496 (Notify user about question dialogs) - Add patch for RH bug #977292 (--force-shutdown closes also factories) [2.32.3-8.el6] - Add patch for RH bug #700733 (Update message counts after mail folder migration) - Add patch for RH bug #975394 (Report errors from calendars in statusbar) - Add patch for RH bug #975409 (Custom message in alarm notification) - Add patch for RH bug #970955 (Contact mail merge improvements) - Add patch for RH bug #971452 (Empty Send/Draft folders in account from startup wizard) [2.32.3-7.el6] - Add patch for RH bug #974647 (Load extensions in GObject::constructed) - Add patch for RH bug #974234 (Crash in try_open_e_book_cb()) [2.32.3-6.el6] - Fix typo in patch for Coverity scan issues - Add patch for RH bug #971820 (Crash in et_get_n_children) [2.32.3-5.el6] - Add patch for some issues found by Coverity scan [2.32.3-4.el6] - Add patch for RH bug #962331 (Initialize dbus-glib threading for GConf) - Add patch for RH bug #689429 (Replace 'Open With' button for too large messages) [2.32.3-3.el6] - Add patch for RH bug #602667 (Crash due to use after mail_msg_free call) - Add patch for RH bug #698246 (Remember password default value for calendars) - Add patch for RH bug #670917 (ItipFormatter - do not check read-only calendars) - Add patch for RH bug #737865 (ItipFormatter - ensure attendee email) - Add patch for RH bug #970650 (Store last attachment load/save path as URI) - Add patch for RH bug #970633 (Contact editor's work Country mnemonic widget) - Add patch for RH bug #949610 (Don't block UI on an attachment load) - Add patch for RH bug #919002 (Prevent message list auto-selection change) - Add patch for RH bug #857003 (Wrong czech translation) [2.32.3-2.el6] - Add patch with some gnome-2-32 branch bug fixes, which landed after 2.32.3 release [2.32.3-1.el6] - Rebase to 2.32.3 - Remove patch for conduit dir fix (obsolete by rebase) - Remove patch for GNOME bug #613639 (obsolete by rebase) - Remove patch for RH bug #585750 (part of rebase) - Remove patch for RH bug #577799 (part of rebase) - Remove patch for RH bug #522157, #632998, #638643 (obsolete by rebase) - Remove patch for RH bug #621517 (part of rebase) - Remove patch for RH bug #632968 (part of rebase) - Remove patch for RH bug #633629 (obsolete by rebase) - Remove patch for RH bug #585931 (part of rebase) - Remove patch for RH bug #666875 (part of rebase) - Remove patch for RH bug #667083 (part of rebase) - Remove patch for RH bug #696881 (part of rebase) - Remove patch for RH bug #805239 (part of rebase) - Remove patch for RH bug #890642 (part of rebase) - Remove patch for RH bug #552805 (part of rebase) evolution-data-server [2.32.3-18.el6] - Add patch for RH bug #1014032 (Prevent a crash in CamelDB) [2.32.3-17.el6] - Add patch for RH bug #1009426 ('no such table' error after upgrade) [2.32.3-16.el6] - Add patch for RH bug #1004784 (Create contact on ownCloud with WebDAV fails) [2.32.3-15.el6] - Update translation patch [2.32.3-14.el6] - Add patch for translation updates [2.32.3-13.el6] - Add patch for RH bug #979722 (Mail connects with weak SSL) - Bump nss version requirement to 3.14 [2.32.3-12.el6] - Add patch for RH bug #991074 (Unnecessary crash due to g_assert() call) [2.32.3-11.el6] - Add patch for RH bug #990380 (CVE-2013-4166) [2.32.3-10.el6] - Add patch for RH bug #950005 (Ignore cached zero-sized files) - Add patch for RH bug #983964 (Do calendar operations in a thread) [2.32.3-9.el6] - Add patch for RH bug #970013 (Disable IMAP+ QResync feature by default) - Add patch for RH bug #983031 (Google book saves other fax as business fax) - Add patch for RH bug #975409 (Custom alarm message for local calendars) [2.32.3-8.el6] - Add patch for RH bug #982681 (Google contact list name changes on load) [2.32.3-7.el6] - Add patch for RH bug #735674 (Add parameter guards to POP3 provider) - Add patch for RH bug #977395 (Be able to close factories with killev) [2.32.3-6.el6] - Add patch for RH bug #700726 (Try to read binary camel summaries from other archs) - Add patch for RH bug #975438 (Category Unmatched search doesn't work with Name contains) [2.32.3-5.el6] - Add patch for RH bug #971621 (Book view blocks factory) - Add patch for RH bug #696620 (Crash of in retrieval_done of an On The Web calendar) [2.32.3-4.el6] - Add patch for some issues found by Coverity scan [2.32.3-3.el6] - Add patch for RH bug #710058 (Expand list inline with comma separator) - Add patch for RH bug #589263 (EFileCache recursive freeze/thaw) - Add patch for RH bug #815371 (Encoded email address shown after paste) - Add patch for RH bug #804651 (Incorrect CalDAV offline setup test) - Add patch for RH bug #739968 (Initialize dbus-glib threading for GConf) - Add patch for RH bug #710005 (Encoded email address shown after list inline expand) - Add patch for RH bug #962499 (GPG decrypt failed with missing signature certificate) - Add patch for RH bug #955587 (GPG and S/MIME parts are not attachments) - Add patch for RH bug #811980 (CalDAV fails to write to Google calendar) - Add patch for RH bug #750916 (Offer also TLS for IMAPS) - Add patch for RH bug #705859 (Calendar code memory leaks) [2.32.3-2.el6] - Add patch with some gnome-2-32 branch bug fixes, which landed after 2.32.3 release [2.32.3-1.el6] - Rebase to 2.32.3 - Remove patch for RH bug #215702 (part of rebase) - Remove patch for GNOME bug #373146 (obsolete by rebase) - Remove patch for 'Remove debug spew from IMAP provider' (part of rebase) - Remove patch for RH bug #576215 (part of rebase) - Remove patch for RH bug #589192 (obsolete by rebase) - Remove patch for RH bug #553556 (part of rebase) - Remove patch for RH bug #605320 (part of rebase) - Remove patch for RH bug #619286 (part of rebase) - Remove patch for RH bug #657117 (part of rebase) - Remove patch for RH bug #634949 (part of rebase) - Remove patch for RH bug #660356 (obsolete by rebase) - Remove patch for RH bug #666879 (part of rebase) - Remove patch for RH bug #734048 (part of rebase) evolution-exchange [2.32.3-16.el6] - Add patch for RH bug #1019434 (evolution-ews searchable GAL) [2.32.3-15.el6] - Add patch for RH bug #1018301 (evolution-ews crash and broken Free/Busy fetch) [2.32.3-14.el6] - Add patch for RH bug #1009470 (evolution-ews crash when GAL not marked for offline sync) - Add patch for RH bug #1005888 (evolution-ews add 'no-alarm-after-start' calendar capability) [2.32.3-13.el6] - Add patch for RH bug #1006336 (evolution-ews fails to download attachments) [2.32.3-12.el6] - Do not ship gtk-doc files (RH bug #1000325) [2.32.3-11.el6] - Add patch to regression of GNOME bug #702922 (Cannot create appointments) [2.32.3-10.el6] - Add patch for some issues found by Coverity scan in evolution-exchange [2.32.3-9.el6] - Update translation patch for evolution-exchange [2.32.3-8.el6] - Add patches for translation updates [2.32.3-7.el6] - Add patch for evolution-ews to match 3.8.5 upstream release [2.32.3-6.el6] - Update patch for evolution-ews to match 3.8.4 upstream release (RH bug #988356) [2.32.3-5.el6] - Add patch for evolution-ews to match 3.8.4 upstream release - Add patch for RH bug #984961 (evolution-ews multiple contacts remove hang) - Add patch for RH bug #985015 (evolution-ews empty search hides contacts) [2.32.3-4.el6] - Add patch for RH bug #984531 (evolution-ews double-free in book backend) [2.32.3-3.el6] - Add patch for evolution-ews to fix account type check in new account wizard [2.32.3-2.el6] - Add patch for evolution-ews to match 3.8.3 upstream release [2.32.3-1.el6] - Rebase to 2.32.3 - Bundle evolution-ews as part of this, with feature parity of its 3.8.2 release evolution-mapi [0.32.2-12] - Fix a copy&paste error in a patch update for RH bug #621941 [0.32.2-11] - Update patch for RH bug #621941 (Created events not shown in OWA) - Add patch for RH bug #1017108 (Shorten delay of calendar open) [0.32.2-10] - Add patch for RH bug #621941 (Created events not shown in OWA) - Add patch for RH bug #906341 (Cannot create book/calendar) [0.32.2-9] - Update patch for RH bug #1005072 (Calendars could not authenticate) [0.32.2-8] - Add patch for RH bug #619842 (Attached email message is empty in forwarded email) [0.32.2-7] - Add patch for RH bug #1005072 (Authentication after migration/restore fails) [0.32.2-6] - Add patch for translation updates - Update patch for issues found by Coverity scan [0.32.2-5] - Bump libmapi requirement to 1.0-4 [0.32.2-4] - Add patch for some issues found by Coverity scan [0.32.2-3] - Add patch for RH bug #909259 (Meeting invite accept duplicates event) [0.32.2-2] - Add patch for RH bug #694134 (Contacts book not searchable) - Add patch for RH bug #625059 (Allow slash in folder names) - Add patch for RH bug #905591 (Refresh folder can fail with Exchange 2010 server) [0.32.2-1] - Rebase to 0.32.2 - Remove patch for RH bug #589193 (obsolete by rebase) - Remove patch for RH bug #602749 (part of rebase) - Remove patch for RH bug #605369 (part of rebase) - Remove patch for RH bug #666492 (obsolete by rebase) - Remove patch for RH bug #902932 (merged to openchange-1.0 patch) - Remove patch for RH bug #903241 (part of rebase) gnome-panel [2.30.2-15] - Rebuild against newer evolution-data-server. Resolves: #973284 gnome-python2-desktop [2.28.0-5.el6] - Rebuild against newer evolution-data-server. Resolves: #973285 gtkhtml3 [3.32.2-2.el6] - Add patch for some issues found by Coverity scan - Add patch for RH bug #577797 (Cursor misplaced after paste) - Add patch for RH bug #615969 (Whitespaces drop on paste) - Add patch for RH bug #627199 (Underline/strikeout misplaced in printout) - Add patch for RH bug #626690 (Paragraph style not drawn after font style change) [3.32.2-1.el6] - Rebase to 3.32.2 - Remove patch for RH bug #588457 (part of rebase) - Remove patch for RH bug #590877 (part of rebase) libgdata [0.6.4-2] - Return back accidentally removed changelog entry [0.6.4-1] - Update to 0.6.4 nautilus-sendto [2.28.2-4] - Rebuild against newer evolution-data-server. Resolves: #973287 openchange [1.0-6] - Add a patch for RH bug #665967 (Free/busy fails to be fetched) pidgin [2.7.9-11.el6] - Rebuild against newer evolution-data-server (RH bug #973288). planner [0.14.4-10] - Resolves: rhbz#973289 rebuild against newer evolution-data-server - Also add planner-0.14.4-edsapi.patch from Fedora 14 package. totem [2.28.6-4] - Change a description of a totem-youtube package [2.28.6-3] - Rebuild against libgdata-0.6.4 Resolves: #883032"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1540");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1540.html");
script_cve_id("CVE-2013-4166");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_copyright("Eero Volotinen");
script_family("Oracle Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"cheese", rpm:"cheese~2.28.1~8.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"control-center", rpm:"control-center~2.28.1~39.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"control-center-devel", rpm:"control-center-devel~2.28.1~39.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"control-center-extra", rpm:"control-center-extra~2.28.1~39.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"control-center-filesystem", rpm:"control-center-filesystem~2.28.1~39.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ekiga", rpm:"ekiga~3.2.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.32.3~30.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~2.32.3~18.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution-data-server-devel", rpm:"evolution-data-server-devel~2.32.3~18.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution-data-server-doc", rpm:"evolution-data-server-doc~2.32.3~18.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.32.3~30.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution-devel-docs", rpm:"evolution-devel-docs~2.32.3~30.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution-exchange", rpm:"evolution-exchange~2.32.3~16.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution-help", rpm:"evolution-help~2.32.3~30.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution-mapi", rpm:"evolution-mapi~0.32.2~12.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution-mapi-devel", rpm:"evolution-mapi-devel~0.32.2~12.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution-perl", rpm:"evolution-perl~2.32.3~30.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution-pst", rpm:"evolution-pst~2.32.3~30.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"evolution-spamassassin", rpm:"evolution-spamassassin~2.32.3~30.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.7.9~11.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.7.9~11.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-panel", rpm:"gnome-panel~2.30.2~15.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-panel-devel", rpm:"gnome-panel-devel~2.30.2~15.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-panel-libs", rpm:"gnome-panel-libs~2.30.2~15.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-applet", rpm:"gnome-python2-applet~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-brasero", rpm:"gnome-python2-brasero~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-bugbuddy", rpm:"gnome-python2-bugbuddy~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-desktop", rpm:"gnome-python2-desktop~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-evince", rpm:"gnome-python2-evince~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-evolution", rpm:"gnome-python2-evolution~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-gnomedesktop", rpm:"gnome-python2-gnomedesktop~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-gnomekeyring", rpm:"gnome-python2-gnomekeyring~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-gnomeprint", rpm:"gnome-python2-gnomeprint~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-gtksourceview", rpm:"gnome-python2-gtksourceview~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-libgtop2", rpm:"gnome-python2-libgtop2~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-libwnck", rpm:"gnome-python2-libwnck~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-metacity", rpm:"gnome-python2-metacity~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-rsvg", rpm:"gnome-python2-rsvg~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-totem", rpm:"gnome-python2-totem~2.28.0~5.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gtkhtml3", rpm:"gtkhtml3~3.32.2~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gtkhtml3-devel", rpm:"gtkhtml3-devel~3.32.2~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libgdata", rpm:"libgdata~0.6.4~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libgdata-devel", rpm:"libgdata-devel~0.6.4~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.7.9~11.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.7.9~11.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.7.9~11.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.7.9~11.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nautilus-sendto", rpm:"nautilus-sendto~2.28.2~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nautilus-sendto-devel", rpm:"nautilus-sendto-devel~2.28.2~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openchange", rpm:"openchange~1.0~6.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openchange-client", rpm:"openchange-client~1.0~6.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openchange-devel", rpm:"openchange-devel~1.0~6.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openchange-devel-docs", rpm:"openchange-devel-docs~1.0~6.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.7.9~11.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.7.9~11.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"pidgin-docs", rpm:"pidgin-docs~2.7.9~11.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.7.9~11.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"planner", rpm:"planner~0.14.4~10.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"planner-devel", rpm:"planner-devel~0.14.4~10.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"planner-eds", rpm:"planner-eds~0.14.4~10.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"totem", rpm:"totem~2.28.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"totem-devel", rpm:"totem-devel~2.28.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"totem-jamendo", rpm:"totem-jamendo~2.28.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"totem-mozplugin", rpm:"totem-mozplugin~2.28.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"totem-nautilus", rpm:"totem-nautilus~2.28.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"totem-upnp", rpm:"totem-upnp~2.28.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"totem-youtube", rpm:"totem-youtube~2.28.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

