// ─── Enums ────────────────────────────────────────────────────────────────────

export type ScanStatus      = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
export type Severity        = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type ModuleStatus    = 'PENDING' | 'RUNNING' | 'DONE' | 'ERROR';
export type UserRole        = 'USER' | 'ADMIN';
export type ModuleCategory  = 'SECURITY' | 'NETWORK' | 'OSINT' | 'SCRAPING';

// ─── Entities ─────────────────────────────────────────────────────────────────

export interface User {
  id:        string;
  username:  string;
  email:     string;
  role:      UserRole;
  isActive:  boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ScanModule {
  id:             string;
  name:           string;
  slug:           string;
  description:    string;
  isActive:       boolean;
  defaultEnabled: boolean;
  category:       ModuleCategory;
}

export interface ScanModuleResult {
  id:            string;
  moduleId:      string;
  status:        ModuleStatus;
  executionTime: number | null;
  rawOutput:     string | null;
  module:        ScanModule;
}

export interface Scan {
  id:             string;
  userId:         string;
  targetUrl:      string;
  description:    string | null;
  status:         ScanStatus;
  depth:          string;
  threads:        number;
  startedAt:      string | null;
  completedAt:    string | null;
  createdAt:      string;
  moduleResults?: ScanModuleResult[];
}

export interface Vulnerability {
  id:             string;
  scanId:         string;
  name:           string;
  severity:       Severity;
  cvssScore:      number | null;
  cveId:          string | null;
  endpoint:       string | null;
  parameter:      string | null;
  description:    string;
  payload:        string | null;
  recommendation: string;
  references:     string[];
  createdAt:      string;
}

export interface Report {
  id:          string;
  scanId:      string;
  format:      string;
  filePath:    string;
  fileSize:    number | null;
  generatedAt: string;
  scan?:       Scan;
}

// ─── API Response shapes ───────────────────────────────────────────────────────
// L'API renvoie { success, data: T }. Axios encapsule dans .data.
// useQuery<{ data: ApiResp<T> }> → data.data.data = T

export interface ApiResp<T> {
  success: boolean;
  data:    T;
}

// Réponses paginées (forme interne : .data.data de la réponse Axios)
export interface PaginatedScans {
  scans:  Scan[];
  total:  number;
  page:   number;
  limit:  number;
}

// Stats vulnérabilités (noms en minuscules comme renvoyés par l'API)
export interface VulnStats {
  critical: number;
  high:     number;
  medium:   number;
  low:      number;
  total:    number;
}

// Stats admin
export interface AdminStats {
  totalUsers:     number;
  totalScans:     number;
  totalVulns:     number;
  scansByStatus:  Record<string, number>;
}
