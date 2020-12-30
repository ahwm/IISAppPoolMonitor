using Microsoft.Web.Administration;
using Nager.PublicSuffix;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Timers;

namespace AppPoolMonitor
{
    public partial class Service1 : ServiceBase
    {
        #region vars
        static int NumFailures
        {
            get
            {
                try
                {
                    return Convert.ToInt32(ConfigurationManager.AppSettings["NumFailures"]);
                }
                catch
                {
                    return 5; // default to 5 failures if there's a problem getting the value from configuration
                }
            }
        }
        static int NumDays
        {
            get
            {
                try
                {
                    return Convert.ToInt32(ConfigurationManager.AppSettings["NumDays"]);
                }
                catch
                {
                    return 30; // default to 30 days if there's a problem getting the value from configuration
                }
            }
        }
        static int Interval
        {
            get
            {
                try
                {
                    return Convert.ToInt32(ConfigurationManager.AppSettings["CheckInterval"]);
                }
                catch
                {
                    return 2; // default to 2 minutes if there's a problem getting the value from configuration
                }
            }
        }
        static int CertInterval
        {
            get
            {
                try
                {
                    return Convert.ToInt32(ConfigurationManager.AppSettings["CertCheckInterval"]);
                }
                catch
                {
                    return 10; // default to 10 minutes if there's a problem getting the value from configuration
                }
            }
        }
        private static string connString;
        private static string Source;
        private static string LogName;
        private static string[] NotificationEmail;
        #endregion

        BackgroundWorker worker;
        Timer timer = new Timer(Interval * 60_000);
        BackgroundWorker certWorker;
        Timer certTimer = new Timer(CertInterval * 60_000);
        DomainParser _parser;
        ConfigMonitor monitor;
        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            connString = ConfigurationManager.ConnectionStrings["ConnectionString"].ConnectionString;
            Source = ConfigurationManager.AppSettings["EventLogSource"];
            LogName = ConfigurationManager.AppSettings["EventLogName"];
            NotificationEmail = ConfigurationManager.AppSettings["NotificationEmail"].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Trim();

            if (!EventLog.SourceExists(Source))
                EventLog.CreateEventSource(Source, LogName);

            EventLog.WriteEntry(Source, "Started " + Source, EventLogEntryType.Information);


            worker = new BackgroundWorker();
            worker.DoWork += Worker_DoWork;
            timer.Elapsed += Timer_Elapsed;
            timer.Start();

            certWorker = new BackgroundWorker();
            certWorker.DoWork += CertWorker_DoWork;
            certTimer.Elapsed += CertTimer_Elapsed;
            certTimer.Start();

            monitor = new ConfigMonitor();
            monitor.Reloaded += Monitor_Reloaded;

            _parser = new DomainParser(new WebTldRuleProvider());
        }

        private void Monitor_Reloaded(object sender, EventArgs e)
        {
            connString = ConfigurationManager.ConnectionStrings["ConnectionString"].ConnectionString;
            Source = ConfigurationManager.AppSettings["EventLogSource"];
            LogName = ConfigurationManager.AppSettings["EventLogName"];
            NotificationEmail = ConfigurationManager.AppSettings["NotificationEmail"].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Trim();

            timer.Stop();
            timer.Interval = Interval * 60_000;
            timer.Start();

            certTimer.Stop();
            certTimer.Interval = CertInterval * 60_000;
            certTimer.Start();
        }

        private void CertTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            certWorker.RunWorkerAsync();
        }

        private void CertWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            // expirations currently does not work correctly
            try
            {
                using (ServerManager manager = new ServerManager())
                {                    
                    SiteCollection siteCollection = manager.Sites;
                    List<string> sites = new List<string>();
                    //List<string> expirations = new List<string>();
                    foreach (Site site in siteCollection)
                    {
                        if (site.State != ObjectState.Started)
                            continue;

                        EventLog.WriteEntry(Source, $"Getting https bindings for {site.Name} (ID: {site.Id})", EventLogEntryType.Information);
                        List<string> bindingNames = new List<string>();
                        List<X509Certificate2> certHashes = new List<X509Certificate2>();
                        foreach (Binding binding in site.Bindings)
                        {
                            bindingNames.Add(binding.Host);
                            if (binding.Protocol == "https" && binding.CertificateHash != null && binding.CertificateHash.Length > 0)
                            {
                                var store = new X509Store("Web Hosting", StoreLocation.LocalMachine);
                                store.Open(OpenFlags.ReadOnly);
                                var storeCerts = store.Certificates.Find(X509FindType.FindByThumbprint, binding.CertificateHash.ToHex(), false);
                                EventLog.WriteEntry(Source, $"storeCerts in Web Hosting for {binding.Host} = {storeCerts.Count}", EventLogEntryType.Information);
                                if (storeCerts.Count > 0)
                                    certHashes.Add(storeCerts[0]);
                                else
                                {
                                    store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                                    store.Open(OpenFlags.ReadOnly);
                                    storeCerts = store.Certificates.Find(X509FindType.FindByThumbprint, binding.CertificateHash.ToHex(), false);
                                    EventLog.WriteEntry(Source, $"storeCerts in My for {binding.Host} = {storeCerts.Count}", EventLogEntryType.Information);
                                    if (storeCerts.Count > 0)
                                        certHashes.Add(storeCerts[0]);
                                    //else
                                    //{
                                    //    expirations.Add(site.Name + " (no certificates in store for " + binding.Host + ", Thumbprint: " + binding.CertificateHash.ToHex() + ")");
                                    //}
                                }
                            }
                            else if (binding.Protocol == "https" && (binding.CertificateHash == null || binding.CertificateHash.Length == 0))
                                sites.Add(site.Name + " (no certificate detected on https binding for " + binding.Host + ")");
                        }
                        foreach (var cert in certHashes)
                        {
                            //EventLog.WriteEntry(Source, $"var cert.NotAfter = {cert.NotAfter}\nvar DateTime.Now = {DateTime.Now}\nvar TotalDays = {(cert.NotAfter - DateTime.Now).TotalDays}", EventLogEntryType.Information);
                            //if ((cert.NotAfter - DateTime.Now).TotalDays < 30)
                            //{
                            //    if (!expirations.Contains(site.Name))
                            //        expirations.Add(site.Name);
                            //}
                            var names = ParseSujectAlternativeNames(cert);
                            if (!bindingNames.Any(x => cert.FriendlyName.Contains(x) || cert.FriendlyName.Contains("*." + x) || names.Contains(x) || names.Contains(_parser.Get(x).RegistrableDomain)))
                            {
                                sites.Add(site.Name);
                                break;
                            }
                        }
                    }
                    SendCertNotification(sites);
                    //SendExpirationNotification(expirations);
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry(Source, $"{ex.Message}\n\n{ex.StackTrace}", EventLogEntryType.Error);
            }
        }

        private void Timer_Elapsed(object sender, ElapsedEventArgs e)
        {
            worker.RunWorkerAsync();
        }

        private void Worker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                using (ServerManager manager = new ServerManager())
                {
                    ApplicationPoolCollection applicationPoolCollection = manager.ApplicationPools;

                    List<string> pools = new List<string>();
                    List<string> poolList = new List<string>();
                    foreach (ApplicationPool applicationPool in applicationPoolCollection)
                    {
                        poolList.Add($"Pool '{applicationPool.Name}' - State: {applicationPool.State}");
                        if (applicationPool.State == ObjectState.Stopped && !applicationPool.Name.ToLower().Contains("trunk"))
                        {
                            ObjectState state = applicationPool.Start();
                            EventLog.WriteEntry(Source, $"Started {applicationPool.Name} application pool(s)", EventLogEntryType.Warning);
                            AddStarted(applicationPool.Name);
                            if (NeedsNotified(applicationPool.Name))
                                pools.Add(applicationPool.Name);
                        }
                    }

                    if (pools.Count > 0)
                        EventLog.WriteEntry(Source, $"Started {pools.Count} application pool(s)", EventLogEntryType.Information);
                    SendNotification(pools);
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry(Source, $"{ex.Message}\n\n{ex.StackTrace}", EventLogEntryType.Error);
            }
        }

        protected override void OnStop()
        {
            EventLog.WriteEntry(Source, "Stopped Application Pool Monitoring Service", EventLogEntryType.Information);
            timer.Stop();
            certTimer.Stop();
        }

        private static void AddStarted(string name)
        {
            using (SqlConnection conn = new SqlConnection(connString))
            {
                conn.Open();
                using (SqlCommand cmd = new SqlCommand("INSERT INTO AppStatus ([AppName], ServerName) VALUES (@Name, @ServerName)", conn))
                {
                    cmd.CommandType = CommandType.Text;
                    cmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.VarChar, 100) { Value = name });
                    cmd.Parameters.Add(new SqlParameter("@ServerName", SqlDbType.VarChar, 50) { Value = Environment.MachineName });
                    cmd.ExecuteNonQuery();
                }
            }
        }

        private static bool NeedsNotified(string name)
        {
            using (SqlConnection conn = new SqlConnection(connString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT COUNT(Id) FROM AppStatus WHERE DateStarted > DATEADD(DAY, @NumDays, GETDATE()) AND [AppName] = @Name AND ServerName = @ServerName", conn))
                {
                    DataSet t = new DataSet();
                    cmd.CommandType = CommandType.Text;
                    cmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.VarChar, 100) { Value = name });
                    cmd.Parameters.Add(new SqlParameter("@ServerName", SqlDbType.VarChar, 50) { Value = Environment.MachineName });
                    cmd.Parameters.Add(new SqlParameter("@NumDays", SqlDbType.Int) { Value = -NumDays });
                    using (SqlDataAdapter data = new SqlDataAdapter(cmd))
                    {
                        data.Fill(t);
                    }
                    int numStarts = Convert.ToInt32(t.Tables[0].Rows[0][0]);
                    return numStarts >= NumFailures;
                }
            }
        }

        private static void SendNotification(List<string> pools)
        {
            if (pools.Count == 0)
                return;

            using (MailMessage m = new MailMessage())
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                foreach (var em in NotificationEmail)
                    m.To.Add(em);
                m.Body = String.Join("\n", pools);
                m.Subject = $"[{Environment.MachineName}] App Pool Notification";
                m.IsBodyHtml = false;

                using (SmtpClient c = new SmtpClient())
                {
                    try
                    {
                        c.Send(m);
                    }
                    catch (Exception ex)
                    {
                        while (ex.InnerException != null)
                            ex = ex.InnerException;

                        EventLog.WriteEntry(Source, $"{ex.Message}\n{ex.StackTrace}", EventLogEntryType.Error);
                    }
                }
            }
        }

        private static void SendCertNotification(List<string> siteNames)
        {
            if (siteNames.Count == 0)
                return;

            using (MailMessage m = new MailMessage())
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                foreach (var em in NotificationEmail)
                    m.To.Add(em);
                m.Body = String.Join("\n", siteNames);
                m.Subject = $"[{Environment.MachineName}] Possible Certificate Mismatch Detected";
                m.IsBodyHtml = false;

                using (SmtpClient c = new SmtpClient())
                {
                    try
                    {
                        c.Send(m);
                    }
                    catch (Exception ex)
                    {
                        while (ex.InnerException != null)
                            ex = ex.InnerException;

                        EventLog.WriteEntry(Source, $"{ex.Message}\n{ex.StackTrace}", EventLogEntryType.Error);
                    }
                }
            }
        }
        
        private static void SendExpirationNotification(List<string> siteNames)
        {
            if (siteNames.Count == 0)
                return;

            using (MailMessage m = new MailMessage())
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                foreach (var em in NotificationEmail)
                    m.To.Add(em);
                m.Body = String.Join("\n", siteNames);
                m.Subject = $"[{Environment.MachineName}] Certificate Expiration Notification (< 30 days until expiration)";
                m.IsBodyHtml = false;

                using (SmtpClient c = new SmtpClient())
                {
                    try
                    {
                        c.Send(m);
                    }
                    catch (Exception ex)
                    {
                        while (ex.InnerException != null)
                            ex = ex.InnerException;

                        EventLog.WriteEntry(Source, $"{ex.Message}\n{ex.StackTrace}", EventLogEntryType.Error);
                    }
                }
            }
        }

        private static IEnumerable<string> ParseSujectAlternativeNames(X509Certificate2 cert)
        {
            Regex sanRex = new Regex(@"^DNS Name=(.*)", RegexOptions.Compiled | RegexOptions.CultureInvariant);

            var sanList = from X509Extension ext in cert.Extensions
                          where ext?.Oid?.FriendlyName?.Equals("Subject Alternative Name", StringComparison.Ordinal) ?? false
                          let data = new AsnEncodedData(ext.Oid, ext.RawData)
                          let text = data.Format(true)
                          from line in text.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                          let match = sanRex.Match(line)
                          where match.Success && match.Groups.Count > 0 && !string.IsNullOrEmpty(match.Groups[1].Value)
                          select match.Groups[1].Value;

            return sanList;
        }
    }
}
