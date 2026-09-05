// Provenance: amitknigam84/lensops  (fixed).
// repo: amitknigam84/lensops
// commit: fe49109aedfe21dea4d24d4d9f2fa3f1ecfb6c84
// parent: 9b87ecc3a44a7fe2a5185cca1fe52441647d5748
// commit_url: https://github.com/amitknigam84/lensops/commit/fe49109aedfe21dea4d24d4d9f2fa3f1ecfb6c84
// cve: 
// license: MIT
// function: setErrorMessage
// relpath: components/KubernetesManagement.tsx
// provenance: agent
// mechanism: missing_auth_guard

}: KubernetesManagementProps) {
  const { token } = useAuth()
  const [kubeconfig, setKubeconfig] = useState('')
  
  // Helper to get auth headers
  const getAuthHeaders = () => {
    const headers: HeadersInit = { 'Content-Type': 'application/json' }
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }
    return headers
  }
  const [isConnected, setIsConnected] = useState(false)
  const [isConnecting, setIsConnecting] = useState(false)
  const [isValidating, setIsValidating] = useState(false)
  const [isResolving, setIsResolving] = useState(false)
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null)
  const [resolutionResult, setResolutionResult] = useState<{
    resolved: boolean
    fixes: string[]
    remainingIssues: string[]
    resolvedKubeconfig: string
    hasChanges: boolean
  } | null>(null)
  const [deployments, setDeployments] = useState<Deployment[]>([])
  const [services, setServices] = useState<Service[]>([])
  const [pods, setPods] = useState<Pod[]>([])
  const [nodes, setNodes] = useState<any[]>([])
  const [configmaps, setConfigmaps] = useState<any[]>([])
  const [secrets, setSecrets] = useState<any[]>([])
  const [events, setEvents] = useState<any[]>([])
  const [cronjobs, setCronjobs] = useState<CronJob[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const [ingresses, setIngresses] = useState<Ingress[]>([])
  const [pvcs, setPvcs] = useState<PVC[]>([])
  const [namespaces, setNamespaces] = useState<Namespace[]>([])
  const [selectedNamespace, setSelectedNamespace] = useState<string>('')
  const [deployedNamespace, setDeployedNamespace] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [selectedDeployments, setSelectedDeployments] = useState<Set<string>>(new Set())
  const [imageUpdates, setImageUpdates] = useState<Map<string, ImageUpdate>>(new Map())
  const [isUpdating, setIsUpdating] = useState(false)
  const [updateMode, setUpdateMode] = useState<'bulk' | 'selective'>('selective')
  const [showDeployments, setShowDeployments] = useState(true)
  const [showServices, setShowServices] = useState(true)
  const [showPods, setShowPods] = useState(true)
  const [showNamespaces, setShowNamespaces] = useState(true)
  const [expandedPodIssues, setExpandedPodIssues] = useState<string | null>(null)
  const [expandedDeploymentIssues, setExpandedDeploymentIssues] = useState<string | null>(null)
  const [activeResourceTab, setActiveResourceTab] = useState<'overview' | 'deployments' | 'pods' | 'services' | 'configmaps' | 'secrets' | 'events' | 'cronjobs' | 'jobs' | 'ingresses' | 'pvcs' | 'flow-tracing' | 'databases' | 'download-images' | 'image-change-report' | 'mongodb-wizard' | 'adminer-wizard'>('overview')
  const [selectedResource, setSelectedResource] = useState<{
    type: 'deployment' | 'service' | 'pod' | 'configmap' | 'secret' | 'cronjob' | 'job' | 'ingress' | 'pvc' | null
    namespace: string
    name: string
  } | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null)
  const [actionModal, setActionModal] = useState<{
    type: 'scale' | 'restart' | 'delete' | null
    resourceType: string
    namespace: string
    name: string
    currentReplicas?: number
  } | null>(null)
  const [isActioning, setIsActioning] = useState(false)
  const [scaleReplicas, setScaleReplicas] = useState<number>(1)
  const [selectedLogPod, setSelectedLogPod] = useState<{
    namespace: string
    name: string
    container?: string
  } | null>(null)
  const [describePod, setDescribePod] = useState<{ namespace: string; name: string } | null>(null)
  const [describePodContent, setDescribePodContent] = useState<string | null>(null)
  const [describePodLoading, setDescribePodLoading] = useState(false)
  const [describePodError, setDescribePodError] = useState<string | null>(null)
  const [showImageComparison, setShowImageComparison] = useState(false)
  const [showBulkUpdateWizard, setShowBulkUpdateWizard] = useState(false)
  const [bulkUpdateSelections, setBulkUpdateSelections] = useState<Set<string>>(new Set())
  const [bulkUpdateImage, setBulkUpdateImage] = useState('')
  const [bulkUpdateStep, setBulkUpdateStep] = useState<'select' | 'preview'>('select')
  const [portForwardModal, setPortForwardModal] = useState<{ service: Service; targetPort: number; localPort: number } | null>(null)
  const [portForwardCopied, setPortForwardCopied] = useState(false)
  const [showCreateSecretModal, setShowCreateSecretModal] = useState(false)
  const [createSecretName, setCreateSecretName] = useState('')
  const [createSecretData, setCreateSecretData] = useState<{ key: string; value: string }[]>([{ key: '', value: '' }])
  const [createSecretSaving, setCreateSecretSaving] = useState(false)
  const [createSecretError, setCreateSecretError] = useState<string | null>(null)
  const [bulkUpdateTagOnly, setBulkUpdateTagOnly] = useState(false)
  // Container-wise update state
  const [bulkUpdateActiveTab, setBulkUpdateActiveTab] = useState<string>('')
  const [bulkUpdateContainerImages, setBulkUpdateContainerImages] = useState<Map<string, string>>(new Map())
  const [bulkUpdateContainerTagOnly, setBulkUpdateContainerTagOnly] = useState<Map<string, boolean>>(new Map())
  const [kubeconfigs, setKubeconfigs] = useState<Array<{
    id: string
    name: string
    kubeconfig: string
    isActive: boolean
    createdAt: string
    updatedAt: string
  }>>([])
  const [imageChangeReportDate, setImageChangeReportDate] = useState<string>(() => {
    const now = new Date()
    return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}-${String(now.getUTCDate()).padStart(2, '0')}`
  })
  const [expandedImageHistoryDeployments, setExpandedImageHistoryDeployments] = useState<Set<string>>(new Set())
  const [imageChangeReportData, setImageChangeReportData] = useState<{
    date: string
    byDeployment: Array<{ namespace: string; deployment: string; changeCount: number; images?: string[] }>
    totalChanges: number
    recentInNamespace?: Array<{ date: string; deployment: string; container?: string; image?: string; oldImage?: string; source?: string; user?: string; at: string }>
    currentDeployments?: Array<{
      deployment: string
      namespace: string
      images: Array<{ container: string; image: string }>
      lastUpdated?: string | null
      changeCount?: number
      imageFlow?: Array<{ createdAt: string; images: Array<{ container: string; image: string }>; revision?: string | number }>
    }>
  } | null>(null)
  const [imageChangeReportLoading, setImageChangeReportLoading] = useState(false)
  const [showKubeconfigManager, setShowKubeconfigManager] = useState(false)
  const [newKubeconfigName, setNewKubeconfigName] = useState('')
  const [newKubeconfigContent, setNewKubeconfigContent] = useState('')
  const [isSavingKubeconfig, setIsSavingKubeconfig] = useState(false)
  // Auto-refresh state
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [refreshInterval, setRefreshInterval] = useState(10) // seconds
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null)

  // Overview, Search, Notifications state
  const [auditLogs, setAuditLogs] = useState<any[]>([])
  const [showSearchModal, setShowSearchModal] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [showNotificationPanel, setShowNotificationPanel] = useState(false)

  // Pod selection for bulk delete
  const [selectedPods, setSelectedPods] = useState<Set<string>>(new Set())
  const [isDeletingPods, setIsDeletingPods] = useState(false)

  // Deleted deployments history for restore
  const [deletedDeployments, setDeletedDeployments] = useState<Array<{
    name: string
    namespace: string
    deletedAt: string
    spec: any
  }>>([])
  const [showDeletedDeployments, setShowDeletedDeployments] = useState(false)

  // Load kubeconfig from manager settings or MongoDB (MongoDB is source of truth)
  useEffect(() => {
    // Priority: manager's personal kubeconfig > MongoDB active kubeconfig
    if (managerKubeconfig) {
      setKubeconfig(managerKubeconfig)
    }
    // MongoDB kubeconfigs will be loaded via loadSavedKubeconfigs
  }, [managerKubeconfig])

  // When a feature is disabled, switch away from its tab
  useEffect(() => {
    if (activeResourceTab === 'image-change-report' && !enableImageChangeReport) {
      setActiveResourceTab('overview')
    }
    if (activeResourceTab === 'databases' && !enableDatabase) {
      setActiveResourceTab('overview')
    }
    if (activeResourceTab === 'mongodb-wizard' && !enableMongoDBWizard) {
      setActiveResourceTab('overview')
    }
    if (activeResourceTab === 'adminer-wizard' && !enableAdminerWizard) {
      setActiveResourceTab('overview')
    }
  }, [enableImageChangeReport, enableDatabase, enableMongoDBWizard, enableAdminerWizard, activeResourceTab])

  // Kubeconfig management removed - using ServiceAccount for cluster access
  // No need to load saved kubeconfigs anymore
  const loadSavedKubeconfigs = async () => {
    // This function is kept for compatibility but does nothing
    // Kubeconfig management has been removed in favor of ServiceAccount
    console.log('ℹ️ Kubeconfig management removed - using ServiceAccount for cluster access')
  }

  const handleSaveKubeconfig = async () => {
    if (!newKubeconfigName.trim() || !newKubeconfigContent.trim()) {
      setErrorMessage('Name and kubeconfig content are required')
      return
    }

    setIsSavingKubeconfig(true)
    setErrorMessage(null)

    try {
      const response = await fetch(`${apiUrl}/k8s/kubeconfigs`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          name: newKubeconfigName.trim(),
          kubeconfig: newKubeconfigContent.trim(),
          isActive: false
        })
      })

      const data = await response.json()
      if (data.success) {
        await loadSavedKubeconfigs()
        setNewKubeconfigName('')
        setNewKubeconfigContent('')
        setShowKubeconfigManager(false)
        setErrorMessage('✅ Kubeconfig saved successfully!')
        setTimeout(() => setErrorMessage(null), 3000)
      } else {
        setErrorMessage(data.error || 'Failed to save kubeconfig')
      }
    } catch (error: any) {
      setErrorMessage('Failed to save kubeconfig: ' + error.message)
    } finally {
      setIsSavingKubeconfig(false)
    }
  }

  const handleActivateKubeconfig = async (id: string) => {
    setIsConnecting(true)
    setErrorMessage(null)

    try {
      const response = await fetch(`${apiUrl}/k8s/kubeconfigs/${id}/activate`, {
        method: 'POST',
        headers: getAuthHeaders()
      })

      const data = await response.json()
      if (data.success) {
        setIsConnected(true)
        setKubeconfig(data.kubeconfig.kubeconfig)
        await loadSavedKubeconfigs()
        setErrorMessage('✅ Successfully connected to cluster. Loading namespaces...')
        try {
          await loadNamespaces(true)
          await loadData()
        } catch (err) {
          console.error('Error loading namespaces:', err)
        }
        setTimeout(() => {
          setErrorMessage('✅ Successfully connected and loaded namespaces')
          setTimeout(() => setErrorMessage(null), 3000)
        }, 1000)
      } else {
        setErrorMessage(data.error || 'Failed to activate kubeconfig')
        setIsConnected(false)
      }
    } catch (error: any) {
      setErrorMessage('Failed to activate kubeconfig: ' + error.message)
      setIsConnected(false)
    } finally {
      setIsConnecting(false)
    }
  }

  const handleDeleteKubeconfig = async (id: string) => {
    if (!confirm('Are you sure you want to delete this kubeconfig?')) {
      return
    }

    try {
      const response = await fetch(`${apiUrl}/k8s/kubeconfigs/${id}`, {
        method: 'DELETE',
        headers: getAuthHeaders()
      })

      const data = await response.json()
      if (data.success) {
        await loadSavedKubeconfigs()
        // If deleted kubeconfig was active, clear connection
        const wasActive = kubeconfigs.find(kc => kc.id === id)?.isActive
        if (wasActive) {
          setIsConnected(false)
          setKubeconfig('')
        }
      }
    } catch (error: any) {
      setErrorMessage('Failed to delete kubeconfig: ' + error.message)
    }
  }

  // Clear validation/resolution results when kubeconfig changes
  useEffect(() => {
    if (validationResult) {
      setValidationResult(null)
    }
    if (resolutionResult) {
      setResolutionResult(null)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kubeconfig])

  // Set initial active tab when bulk update selections change
  useEffect(() => {
    if (showBulkUpdateWizard && bulkUpdateSelections.size > 0 && !bulkUpdateActiveTab) {
      // Check if there are main containers or sidecar containers
      let hasMainContainers = false
      let hasSidecarContainers = false
      
      deployments.forEach((deployment) => {
        const key = `${deployment.namespace}/${deployment.name}`
        if (bulkUpdateSelections.has(key)) {
          deployment.containers.forEach((container) => {
            const isSidecar = container.name.toLowerCase().includes('sidecar')
            if (isSidecar) {
              hasSidecarContainers = true
            } else {
              hasMainContainers = true
            }
          })
        }
      })
      
      // Set to 'main' if main containers exist, otherwise 'sidecar' if sidecar containers exist
      if (hasMainContainers) {
        setBulkUpdateActiveTab('main')
      } else if (hasSidecarContainers) {
        setBulkUpdateActiveTab('sidecar')
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showBulkUpdateWizard, bulkUpdateSelections.size])

  const handleResolve = async () => {
    if (!kubeconfig.trim()) {
      setErrorMessage('Please paste or upload a kubeconfig file')
      setResolutionResult(null)
      return
    }

    setIsResolving(true)
    setErrorMessage(null)
    setResolutionResult(null)

    try {
      const response = await fetch(`${apiUrl}/k8s/resolve`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ kubeconfig }),
      })

      const data = await response.json()

      if (data.success) {
        setResolutionResult({
          resolved: data.resolved,
          fixes: data.fixes || [],
          remainingIssues: data.remainingIssues || [],
          resolvedKubeconfig: data.resolvedKubeconfig,
          hasChanges: data.hasChanges,
        })

        if (data.resolved && data.hasChanges) {
          setErrorMessage(
            `✅ Resolved ${data.fixes.length} issue(s). Review the changes below and click "Apply Fixes" to update.`
          )
        } else if (data.resolved) {
          setErrorMessage('✅ No issues found to resolve')
        } else {
          setErrorMessage('⚠️ Some issues could not be auto-resolved')
        }

        // Auto-validate the resolved config
        if (data.resolvedKubeconfig) {
          const validateResponse = await fetch(`${apiUrl}/k8s/validate`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ kubeconfig: data.resolvedKubeconfig }),
          })

          const validateData = await validateResponse.json()
          if (validateData.valid) {
            setValidationResult({
              valid: true,
              info: validateData.info,
            })
          } else {
            setValidationResult({
              valid: false,
              issues: validateData.issues,
              suggestions: validateData.suggestions,
              info: validateData.info,
            })
          }
        }
      } else {
        setErrorMessage(data.message || 'Failed to resolve kubeconfig issues')
      }
    } catch (error: any) {
      setErrorMessage(error.message || 'Failed to resolve kubeconfig')
    } finally {
      setIsResolving(false)
    }
  }

  const handleApplyFixes = () => {
    if (resolutionResult && resolutionResult.resolvedKubeconfig) {
      setKubeconfig(resolutionResult.resolvedKubeconfig)
      setResolutionResult(null)
      setErrorMessage('✅ Fixed kubeconfig applied. You can now validate or connect.')
      setTimeout(() => setErrorMessage(null), 5000)
    }
  }

  const handleValidate = async () => {
    if (!kubeconfig.trim()) {
      setErrorMessage('Please paste or upload a kubeconfig file')
      setValidationResult(null)
      return
    }

    setIsValidating(true)
    setErrorMessage(null)
    setValidationResult(null)

    try {
      const response = await fetch(`${apiUrl}/k8s/validate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ kubeconfig }),
      })

      const data = await response.json()

      if (data.valid) {
        setValidationResult({
          valid: true,
          info: data.info,
        })
        setErrorMessage('✅ Kubeconfig is valid and ready to connect')
        setTimeout(() => setErrorMessage(null), 5000)
      } else {
        setValidationResult({
          valid: false,
          issues: data.issues || [],
          suggestions: data.suggestions || [],
          info: data.info,
        })
      }
    } catch (error: any) {
      setErrorMessage(error.message || 'Failed to validate kubeconfig')
      setValidationResult({
        valid: false,
        issues: ['Validation request failed'],
        suggestions: ['Check your connection to the API server'],
      })
    } finally {
      setIsValidating(false)
    }
  }

  const handleConnect = async () => {
    if (!kubeconfig.trim()) {
      setErrorMessage('Please paste or upload a kubeconfig file')
      return
    }

    setIsConnecting(true)
    setErrorMessage(null)

    try {
      const response = await fetch(`${apiUrl}/k8s/connect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ kubeconfig }),
      })

      const data = await response.json()

      if (response.ok && data.success) {
        setIsConnected(true)
        setValidationResult({
          valid: true,
          info: data.info,
        })
        
        // Save kubeconfig to MongoDB for retention (MongoDB is source of truth)
        try {
          const saveResponse = await fetch(`${apiUrl}/k8s/kubeconfigs`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({
              name: `Kubeconfig ${new Date().toLocaleString()}`,
              kubeconfig: kubeconfig,
              isActive: true // Set as active since user just connected with it
            })
          })
          const saveData = await saveResponse.json()
          if (saveData.success) {
            console.log('✅ Kubeconfig saved to MongoDB for retention')
            // Reload kubeconfigs list to show the newly saved one
            await loadSavedKubeconfigs()
            // Clear localStorage since MongoDB is now the source of truth
            storage.removeLocal(STORAGE_KEYS.KUBECONFIG)
          }
        } catch (saveError) {
          console.error('Failed to save kubeconfig to MongoDB:', saveError)
          // Fallback to localStorage only if MongoDB save fails
          storage.setLocal(STORAGE_KEYS.KUBECONFIG, kubeconfig)
        }
        
        setErrorMessage('✅ Successfully connected to cluster. Kubeconfig saved to MongoDB. Loading namespaces...')
        // Load namespaces immediately after connection (skip connection check since we just connected)
        try {
          await loadNamespaces(true)
          // Always load data after namespaces are loaded (defaults to 'all' to show all resources)
          await loadData()
        } catch (err) {
          console.error('Error loading namespaces after connection:', err)
          setErrorMessage('✅ Connected, but failed to load namespaces. Click "Load Namespaces" to retry.')
        }
        setTimeout(() => {
          if (namespaces.length > 0) {
            setErrorMessage('✅ Successfully connected and loaded namespaces')
          } else {
            setErrorMessage('✅ Connected. Click "Load Namespaces" to fetch namespaces.')
          }
          setTimeout(() => setErrorMessage(null), 5000)
        }, 1000)
      } else {
        // Handle validation errors or connection errors
        if (data.issues && data.suggestions) {
          setValidationResult({
            valid: data.valid || false,
            issues: data.issues,
            suggestions: data.suggestions,
            info: data.info,
          })
        }
        setErrorMessage(data.message || 'Failed to connect to cluster')
        setIsConnected(false)
      }
    } catch (error: any) {
      setErrorMessage(error.message || 'Failed to connect to cluster')
      setIsConnected(false)
    } finally {
      setIsConnecting(false)
    }
  }

  const loadNamespaces = async (skipConnectionCheck = false) => {
    if (!skipConnectionCheck && !isConnected) {
      setErrorMessage('Please connect to a Kubernetes cluster first')
      return
    }
    
    setIsLoading(true)
    setErrorMessage(null)
    
    try {
      console.log('📋 Loading namespaces from:', `${apiUrl}/k8s/namespaces`)
      const response = await fetch(`${apiUrl}/k8s/namespaces`, {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {},
      })
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Unknown error' }))
        throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`)
      }
      
      const data = await response.json()
      console.log('📋 Namespaces response:', data)
      
      if (data.success && data.namespaces) {
        setNamespaces(data.namespaces)
        setIsConnected(true) // ✅ Mark as connected after successfully loading namespaces
        
        // Always use deployed namespace (from ServiceAccount)
        const namespaceToUse = data.podNamespace || (data.namespaces.length > 0 ? data.namespaces[0].name : null);
        
        if (namespaceToUse) {
          setDeployedNamespace(namespaceToUse)
          setSelectedNamespace(namespaceToUse)
          console.log('📌 Using deployed namespace:', namespaceToUse)
          // Automatically load resources for the deployed namespace
          console.log('📦 Loading resources from deployed namespace:', namespaceToUse)
          setTimeout(() => {
            loadData()
          }, 100)
        } else {
          setErrorMessage('⚠️ No namespace found. Please check POD_NAMESPACE configuration.')
        }
      } else {
        setErrorMessage(data.message || data.error || 'Failed to load namespaces')
      }
    } catch (error: any) {
      console.error('❌ Failed to load namespaces:', error)
      setErrorMessage(error.message || 'Failed to load namespaces. Please check your connection and try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const loadNodes = async () => {
    if (!isConnected) return
    try {
      const response = await fetch(`${apiUrl}/k8s/nodes`)
      const data = await response.json()
      if (response.ok && data?.nodes) {
        setNodes(data.nodes)
      } else {
        console.warn('⚠️ Failed to load nodes:', data?.message || data?.error)
        setNodes([])
      }
    } catch (error: any) {
      console.error('❌ Failed to load nodes:', error)
      setNodes([])
    }
  }

  const loadImageChangeReport = async () => {
    if (!apiUrl) return
    const namespaceToUse = deployedNamespace || selectedNamespace
    if (!namespaceToUse || namespaceToUse === 'all') {
      setErrorMessage('No namespace available. Connect to the cluster so the report is scoped to your deployed namespace.')
      return
    }
    setImageChangeReportLoading(true)
    setImageChangeReportData(null)
    setErrorMessage(null)
    try {
      const params = new URLSearchParams({ date: imageChangeReportDate, namespace: namespaceToUse })
      const response = await fetch(`${apiUrl}/k8s/image-change-report?${params}`)
      const data = await response.json()
      if (response.ok && data.success) {
        setImageChangeReportData({
          date: data.date,
          byDeployment: data.byDeployment || [],
          totalChanges: data.totalChanges ?? 0,
          recentInNamespace: data.recentInNamespace || [],
          currentDeployments: data.currentDeployments || [],
        })
      } else {
        setErrorMessage(data.message || 'Failed to load image change report')
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load image change report')
    } finally {
      setImageChangeReportLoading(false)
    }
  }

  const loadData = async () => {
    if (!isConnected) {
      console.log('⚠️ Not connected, skipping loadData')
      return
    }
    
    // Always use deployed namespace (from ServiceAccount)
    const namespaceToUse = deployedNamespace || selectedNamespace
    if (!namespaceToUse || namespaceToUse === 'all') {
      console.log('⚠️ No namespace available, waiting for namespace detection...')
      // If we have apiUrl but no namespace yet, try to load namespaces
      if (apiUrl && !deployedNamespace) {
        loadNamespaces(true)
      }
      // Don't clear existing data if we're just waiting for namespace
      // This prevents "no resources" flash when namespace is temporarily unavailable
      return
    }

    setIsLoading(true)
    setErrorMessage(null)
    
    // Don't clear data here - let the API responses determine what to show
    // This prevents "no resources" flash during refresh

    try {
      // Always use deployed namespace
      const namespaceParam = namespaceToUse
      console.log('📦 Loading resources from deployed namespace:', namespaceParam)
      
      const [deploymentsRes, servicesRes, podsRes, configmapsRes, secretsRes, eventsRes, cronjobsRes, jobsRes, ingressesRes, pvcsRes] = await Promise.all([
        fetch(`${apiUrl}/k8s/deployments?namespace=${namespaceParam}`),
        fetch(`${apiUrl}/k8s/services?namespace=${namespaceParam}`),
        fetch(`${apiUrl}/k8s/pods?namespace=${namespaceParam}`),
        fetch(`${apiUrl}/k8s/configmaps?namespace=${namespaceParam}`).catch((err) => {
          console.warn('⚠️ ConfigMaps fetch failed:', err);
          return { ok: false, status: 500, json: async () => ({ success: false, configmaps: [], error: err.message }) };
        }),
        fetch(`${apiUrl}/k8s/secrets?namespace=${namespaceParam}`).catch((err) => {
          console.warn('⚠️ Secrets fetch failed:', err);
          return { ok: false, status: 500, json: async () => ({ success: false, secrets: [], error: err.message }) };
        }),
        fetch(`${apiUrl}/k8s/events?namespace=${namespaceParam}`).catch((err) => {
          console.warn('⚠️ Events fetch failed:', err);
          return { ok: false, status: 500, json: async () => ({ success: false, events: [], error: err.message }) };
        }),
        fetch(`${apiUrl}/k8s/cronjobs?namespace=${namespaceParam}`).catch((err) => {
          console.warn('⚠️ CronJobs fetch failed:', err);
          return { ok: false, status: 500, json: async () => ({ success: false, cronjobs: [], error: err.message }) };
        }),
        fetch(`${apiUrl}/k8s/jobs?namespace=${namespaceParam}`).catch((err) => {
          console.warn('⚠️ Jobs fetch failed:', err);
          return { ok: false, status: 500, json: async () => ({ success: false, jobs: [], error: err.message }) };
        }),
        fetch(`${apiUrl}/k8s/ingresses?namespace=${namespaceParam}`).catch((err) => {
          console.warn('⚠️ Ingresses fetch failed:', err);
          return { ok: false, status: 500, json: async () => ({ success: false, ingresses: [], error: err.message }) };
        }),
        fetch(`${apiUrl}/k8s/pvcs?namespace=${namespaceParam}`).catch((err) => {
          console.warn('⚠️ PVCs fetch failed:', err);
          return { ok: false, status: 500, json: async () => ({ success: false, pvcs: [], error: err.message }) };
        }),
      ])

      const deploymentsData = await deploymentsRes.json()
      const servicesData = await servicesRes.json()
      const podsData = await podsRes.json()

      console.log('📦 Deployments response:', deploymentsData)
      console.log('📦 Services response:', servicesData)
      console.log('📦 Pods response:', podsData)

      if (deploymentsData.success) {
        console.log('✅ Setting deployments:', deploymentsData.deployments?.length || 0)
        setDeployments(deploymentsData.deployments || [])
      } else {
        console.error('❌ Deployments API error:', deploymentsData.error || deploymentsData.message)
        // Only clear data on client errors (4xx), keep existing data on server errors (5xx) or network issues
        // This prevents "no resources" flash during refresh when there are transient errors
        if (deploymentsRes.status >= 400 && deploymentsRes.status < 500) {
          setDeployments([])
        } else {
          console.warn('⚠️ Keeping existing deployments due to server/network error')
        }
      }
      
      if (servicesData.success) {
        console.log('✅ Setting services:', servicesData.services?.length || 0)
        setServices(servicesData.services || [])
      } else {
        console.error('❌ Services API error:', servicesData.error || servicesData.message)
        // Only clear data on client errors (4xx), keep existing data on server errors (5xx) or network issues
        if (servicesRes.status >= 400 && servicesRes.status < 500) {
          setServices([])
        } else {
          console.warn('⚠️ Keeping existing services due to server/network error')
        }
      }
      
      if (podsData.success) {
        const podsArray = podsData.pods || []
        
        // Remove duplicates based on namespace + name
        const uniquePods = podsArray.reduce((acc: Map<string, Pod>, pod: Pod) => {
          const key = `${pod.namespace}/${pod.name}`
          if (!acc.has(key)) {
            acc.set(key, pod)
          } else {
            console.warn(`⚠️ Duplicate pod found: ${key}`)
          }
          return acc
        }, new Map<string, Pod>())
        
        const deduplicatedPods: Pod[] = Array.from(uniquePods.values())
        
        // Filter by namespace if a specific namespace is selected (not 'all')
        const filteredPods: Pod[] = selectedNamespace && selectedNamespace !== 'all' 
          ? deduplicatedPods.filter((pod: Pod) => pod.namespace === selectedNamespace)
          : deduplicatedPods
        
        console.log('✅ Setting pods:', {
          original: podsArray.length,
          afterDedup: deduplicatedPods.length,
          afterFilter: filteredPods.length,
          namespace: namespaceParam,
          selectedNamespace: selectedNamespace
        })
        
        if (podsArray.length !== filteredPods.length) {
          console.warn(`⚠️ Pod count mismatch: API returned ${podsArray.length}, displaying ${filteredPods.length}`)
        }
        
        setPods(filteredPods)
      } else {
        console.error('❌ Pods API error:', podsData.error || podsData.message)
        // Only clear data on client errors (4xx), keep existing data on server errors (5xx) or network issues
        if (podsRes.status >= 400 && podsRes.status < 500) {
          setPods([])
        } else {
          console.warn('⚠️ Keeping existing pods due to server/network error')
        }
      }

      const configmapsData = await configmapsRes.json()
      if (configmapsData.success) {
        console.log('✅ Setting configmaps:', configmapsData.configmaps?.length || 0)
        setConfigmaps(configmapsData.configmaps || [])
      } else {
        console.error('❌ ConfigMaps API error:', configmapsData.error || configmapsData.message)
        setConfigmaps([])
      }

      const secretsData = await secretsRes.json()
      if (secretsData.success) {
        setSecrets(secretsData.secrets || [])
      } else {
        setSecrets([])
      }

      const eventsData = await eventsRes.json()
      if (eventsData.success) {
        console.log('✅ Setting events:', eventsData.events?.length || 0)
        setEvents(eventsData.events || [])
      } else {
        console.error('❌ Events API error:', eventsData.error || eventsData.message)
        setEvents([])
      }

      // Handle CronJobs
      try {
        const cronjobsData = await cronjobsRes.json()
        if (cronjobsData.success) {
          console.log('✅ Setting cronjobs:', cronjobsData.cronjobs?.length || 0)
          setCronjobs(cronjobsData.cronjobs || [])
        } else {
          console.error('❌ CronJobs API error:', cronjobsData.error || cronjobsData.message, cronjobsData.details)
          // Don't show error if it's just that there are no cronjobs (404 or empty list)
          if (cronjobsRes.status !== 404 && !cronjobsData.message?.includes('not found')) {
            console.warn('⚠️ CronJobs fetch warning:', cronjobsData.message)
          }
          setCronjobs([])
        }
      } catch (cronjobsError: any) {
        console.error('❌ Failed to parse CronJobs response:', cronjobsError)
        setCronjobs([])
      }

      // Handle Jobs
      try {
        const jobsData = await jobsRes.json()
        if (jobsData.success) {
          console.log('✅ Setting jobs:', jobsData.jobs?.length || 0)
          setJobs(jobsData.jobs || [])
        } else {
          console.error('❌ Jobs API error:', jobsData.error || jobsData.message, jobsData.details)
          // Don't show error if it's just that there are no jobs (404 or empty list)
          if (jobsRes.status !== 404 && !jobsData.message?.includes('not found')) {
            console.warn('⚠️ Jobs fetch warning:', jobsData.message)
          }
          setJobs([])
        }
      } catch (jobsError: any) {
        console.error('❌ Failed to parse Jobs response:', jobsError)
        setJobs([])
      }

      // Handle Ingresses
      try {
        const ingressesData = await ingressesRes.json()
        if (ingressesData.success) {
          setIngresses(ingressesData.ingresses || [])
        } else {
          setIngresses([])
        }
      } catch (ingressesError: any) {
        console.error('❌ Failed to parse Ingresses response:', ingressesError)
        setIngresses([])
      }

      // Handle PVCs
      try {
        const pvcsData = await pvcsRes.json()
        if (pvcsData.success) {
          setPvcs(pvcsData.pvcs || [])
        } else {
          setPvcs([])
        }
      } catch (pvcsError: any) {
        console.error('❌ Failed to parse PVCs response:', pvcsError)
        setPvcs([])
      }

      // Check for HTTP errors
      if (!deploymentsRes.ok) {
        console.error('❌ Deployments HTTP error:', deploymentsRes.status, deploymentsRes.statusText)
        setErrorMessage(`Failed to fetch deployments: ${deploymentsRes.status} ${deploymentsRes.statusText}`)
      }
      if (!servicesRes.ok) {
        console.error('❌ Services HTTP error:', servicesRes.status, servicesRes.statusText)
        setErrorMessage(`Failed to fetch services: ${servicesRes.status} ${servicesRes.statusText}`)
      }
      if (!podsRes.ok) {
        console.error('❌ Pods HTTP error:', podsRes.status, podsRes.statusText)
        setErrorMessage(`Failed to fetch pods: ${podsRes.status} ${podsRes.statusText}`)
      }
    } catch (error: any) {
      setErrorMessage(error.message || 'Failed to load cluster data')
    } finally {
      setIsLoading(false)
      setLastRefreshed(new Date())
    }
  }


  // Automatically load namespaces and resources on mount when apiUrl is available
  useEffect(() => {
    if (apiUrl && !isConnected && !isConnecting) {
      console.log('🚀 Auto-connecting to Kubernetes cluster via ServiceAccount...')
      loadNamespaces(true) // Skip connection check since we're auto-connecting
    }
  }, [apiUrl]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (isConnected && selectedNamespace) {
      console.log('🔄 Namespace changed to:', selectedNamespace, '- Loading resources...')
      // Clear previous data when namespace changes
      setDeployments([])
      setPods([])
      setNodes([])
      setServices([])
      setConfigmaps([])
      setEvents([])
      setCronjobs([])
      setJobs([])
      // Load new data for the selected namespace
      loadData()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedNamespace, isConnected])

  useEffect(() => {
    if (isConnected) {
      loadNodes()
    } else {
      setNodes([])
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isConnected])

  // Auto-refresh effect
  useEffect(() => {
    if (!autoRefresh || !isConnected) return
    
    const interval = setInterval(async () => {
      console.log('🔄 Auto-refreshing data...')
      const currentTab = activeResourceTab
      await loadData()
      setActiveResourceTab(currentTab)
      setLastRefreshed(new Date())
    }, refreshInterval * 1000)
    
    return () => clearInterval(interval)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoRefresh, refreshInterval, isConnected, deployedNamespace, selectedNamespace])

  const handleImageChange = (
    namespace: string,
    deploymentName: string,
    containerName: string,
    newImage: string,
    originalImage: string
  ) => {
    const key = `${namespace}/${deploymentName}/${containerName}`
    const newUpdates = new Map(imageUpdates)
    
    if (newImage === originalImage) {
      newUpdates.delete(key)
    } else {
      newUpdates.set(key, {
        namespace: namespace,
        deployment: deploymentName,
        container: containerName,
        image: newImage,
        originalImage,
      })
    }
    
    setImageUpdates(newUpdates)
  }

  // Helper function to extract base image (without tag)
  const getBaseImage = (image: string): string => {
    // Remove tag if present (format: image:tag)
    if (image.includes(':')) {
      // Check if it's a port number (registry:port/image:tag)
      const parts = image.split(':')
      if (parts.length > 2) {
        // Has port, get everything before the last colon
        const lastColonIndex = image.lastIndexOf(':')
        return image.substring(0, lastColonIndex)
      } else {
        // Simple format: image:tag
        return parts[0]
      }
    }
    // Remove digest if present (format: image@sha256:...)
    if (image.includes('@')) {
      return image.split('@')[0]
    }
    return image
  }

  // Helper function to apply tag-only update
  const applyTagOnlyUpdate = (originalImage: string, newTag: string): string => {
    const baseImage = getBaseImage(originalImage)
    return `${baseImage}:${newTag}`
  }

  const handleBulkImageUpdate = (newImage: string) => {
    const newUpdates = new Map<string, ImageUpdate>()
    
    deployments.forEach((deployment) => {
      deployment.containers.forEach((container) => {
        const key = `${selectedNamespace}/${deployment.name}/${container.name}`
        newUpdates.set(key, {
          namespace: selectedNamespace,
          deployment: deployment.name,
          container: container.name,
          image: newImage,
          originalImage: container.image,
        })
      })
    })
    
    setImageUpdates(newUpdates)
  }

  const handleSaveSingleImage = async (namespace: string, deployment: string, container: string, newImage: string, originalImage: string) => {
    if (newImage === originalImage) {
      setErrorMessage('Image unchanged')
      setTimeout(() => setErrorMessage(null), 2000)
      return
    }

    if (!newImage || newImage.trim() === '') {
      setErrorMessage('Please enter a valid image name')
      setTimeout(() => setErrorMessage(null), 2000)
      return
    }

    // Validate required fields
    const trimmedNamespace = namespace?.trim()
    const trimmedDeployment = deployment?.trim()
    const trimmedContainer = container?.trim()
    const trimmedImage = newImage.trim()

    if (!trimmedNamespace || !trimmedDeployment || !trimmedContainer) {
      setErrorMessage('Missing required fields: namespace, deployment, or container name')
      setTimeout(() => setErrorMessage(null), 3000)
      return
    }

    // Ensure deployment name doesn't contain namespace (some APIs return it as namespace/name)
    let deploymentName = trimmedDeployment
    if (trimmedDeployment.includes('/')) {
      const parts = trimmedDeployment.split('/').filter(p => p && p.trim() !== '')
      deploymentName = parts.length > 0 ? parts[parts.length - 1] : trimmedDeployment
      console.log('Extracted deployment name:', { original: trimmedDeployment, extracted: deploymentName, parts })
    }

    // Final validation after extraction
    if (!deploymentName || deploymentName.trim() === '') {
      setErrorMessage('Invalid deployment name after processing')
      setTimeout(() => setErrorMessage(null), 3000)
      return
    }

    setIsUpdating(true)
    setErrorMessage(null)

    try {
      const updatePayload = {
        namespace: String(trimmedNamespace),
        deployment: String(deploymentName),
        container: String(trimmedContainer),
        image: String(trimmedImage)
      }
      
      console.log('Saving image update:', { 
        namespace: trimmedNamespace, 
        deployment: deploymentName, 
        container: trimmedContainer, 
        image: trimmedImage,
        originalDeployment: deployment,
        payload: updatePayload
      })
      
      const response = await fetch(`${apiUrl}/k8s/update-images`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          updates: [updatePayload],
          source: 'ui-single'
        }),
      })

      // Check if response is ok before parsing JSON
      if (!response.ok) {
        const errorText = await response.text()
        let errorData
        try {
          errorData = JSON.parse(errorText)
        } catch {
          errorData = { message: errorText || `HTTP ${response.status}: ${response.statusText}` }
        }
        throw new Error(errorData.error || errorData.message || `HTTP ${response.status}: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.success || (data.updated && data.updated > 0)) {
        setErrorMessage(`✅ Successfully updated ${container} image in ${deployment}`)
        // Remove from pending updates
        const key = `${namespace}/${deployment}/${container}`
        const newUpdates = new Map(imageUpdates)
        newUpdates.delete(key)
        setImageUpdates(newUpdates)
        await loadData()
        setTimeout(() => setErrorMessage(null), 5000)
      } else {
        // Check if there are errors in the response
        const errorMsg = data.errors && data.errors.length > 0
          ? data.errors[0].error || data.errors[0].message
          : data.error || data.message
        const errorDetails = data.errors && data.errors.length > 0 && data.errors[0].deployment
          ? ` (${data.errors[0].deployment}/${data.errors[0].container})`
          : ''
        setErrorMessage(
          `❌ Failed to update image${errorDetails}: ${errorMsg || 'Unknown error'}`
        )
        setTimeout(() => setErrorMessage(null), 10000)
      }
    } catch (error: any) {
      console.error('Error updating image:', error)
      setErrorMessage(`❌ Failed to update image: ${error.message || 'Network error. Please check if the API server is running and you are connected to the cluster.'}`)
      setTimeout(() => setErrorMessage(null), 10000)
    } finally {
      setIsUpdating(false)
    }
  }

  const handleUpdateImages = async () => {
    console.log('🔄 handleUpdateImages called')
    console.log('📦 imageUpdates size:', imageUpdates.size)
    console.log('📦 imageUpdates:', Array.from(imageUpdates.entries()))
    
    if (imageUpdates.size === 0) {
      setErrorMessage('No image updates to apply')
      return
    }

    setIsUpdating(true)
    setErrorMessage(null)

    try {
      const updates = Array.from(imageUpdates.values())
      console.log('📋 All updates:', updates)
      
      // If selective mode, only update selected deployments
      let updatesToApply = updates
      if (updateMode === 'selective') {
        console.log('🎯 Selective mode - selectedDeployments:', Array.from(selectedDeployments))
        updatesToApply = updates.filter((update) => {
          const key = `${update.namespace}/${update.deployment}`
          return selectedDeployments.has(key)
        })
        console.log('✅ Filtered updates to apply:', updatesToApply)
      }

      if (updatesToApply.length === 0) {
        console.log('⚠️ No deployments selected')
        setErrorMessage('Please select deployments to update or switch to bulk mode')
        setIsUpdating(false)
        return
      }

      console.log('🚀 Making API call to update images:', updatesToApply)
      const response = await fetch(`${apiUrl}/k8s/update-images`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ updates: updatesToApply, source: updateMode === 'selective' ? 'ui-selective' : 'ui-bulk' }),
      })
      console.log('📡 API response status:', response.status)

      // Check if response is ok before parsing JSON
      if (!response.ok) {
        const errorText = await response.text()
        let errorData
        try {
          errorData = JSON.parse(errorText)
        } catch {
          errorData = { message: errorText || `HTTP ${response.status}: ${response.statusText}` }
        }
        throw new Error(errorData.error || errorData.message || `HTTP ${response.status}: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.success) {
        // All updates succeeded
        setErrorMessage(`✅ Successfully updated ${data.updated || updatesToApply.length} container(s)`)
        setImageUpdates(new Map())
        setSelectedDeployments(new Set())
        await loadData()
        setTimeout(() => setErrorMessage(null), 5000)
      } else if (data.updated && data.updated > 0) {
        // Partial success - some succeeded, some failed
        const errorDetails = data.errors && data.errors.length > 0
          ? data.errors.map((e: any) => `${e.deployment}/${e.container}: ${e.error}`).join('; ')
          : 'See details above'
        setErrorMessage(
          `⚠️ Partial update: ${data.updated} succeeded, ${data.failed || 0} failed. ${errorDetails}`
        )
        // Clear successful updates from the pending list
        if (data.results && Array.isArray(data.results)) {
          const newUpdates = new Map(imageUpdates)
          data.results.forEach((result: any) => {
            const key = `${result.namespace}/${result.deployment}/${result.container}`
            newUpdates.delete(key)
          })
          setImageUpdates(newUpdates)
        }
        await loadData()
        setTimeout(() => setErrorMessage(null), 8000)
      } else {
        // All updates failed
        const errorMsg = data.errors && data.errors.length > 0
          ? data.errors.map((e: any) => `${e.deployment}/${e.container}: ${e.error}`).join('; ')
          : data.error || data.message || 'Unknown error'
        setErrorMessage(`❌ Failed to update images: ${errorMsg}`)
        setTimeout(() => setErrorMessage(null), 10000)
      }
    } catch (error: any) {
      console.error('Error updating images:', error)
      setErrorMessage(`❌ Failed to update images: ${error.message || 'Network error. Please check if the API server is running and you are connected to the cluster.'}`)
      setTimeout(() => setErrorMessage(null), 10000)
    } finally {
      setIsUpdating(false)
    }
  }

  const toggleDeploymentSelection = (namespace: string, deploymentName: string) => {
    const key = `${namespace}/${deploymentName}`
    const newSelected = new Set(selectedDeployments)
    
    if (newSelected.has(key)) {
      newSelected.delete(key)
    } else {
      newSelected.add(key)
    }
    
    setSelectedDeployments(newSelected)
  }

  // Bulk Update Wizard Functions
  const handleSelectAllBulkUpdate = () => {
    if (bulkUpdateSelections.size === deployments.length) {
      setBulkUpdateSelections(new Set())
    } else {
      const allKeys = new Set(deployments.map(d => `${d.namespace}/${d.name}`))
      setBulkUpdateSelections(allKeys)
    }
  }

  const toggleBulkUpdateSelection = (namespace: string, name: string) => {
    const key = `${namespace}/${name}`
    const newSelected = new Set(bulkUpdateSelections)
    
    if (newSelected.has(key)) {
      newSelected.delete(key)
    } else {
      newSelected.add(key)
    }
    
    setBulkUpdateSelections(newSelected)
  }

  const handleBulkUpdateApply = async () => {
    if (bulkUpdateSelections.size === 0) {
      setErrorMessage('Please select at least one deployment')
      return
    }

    if (!bulkUpdateActiveTab || (bulkUpdateActiveTab !== 'main' && bulkUpdateActiveTab !== 'sidecar')) {
      setErrorMessage('Please select a container tab (Main or Sidecar)')
      return
    }

    const containerImage = bulkUpdateContainerImages.get(bulkUpdateActiveTab) || ''
    const containerTagOnly = bulkUpdateContainerTagOnly.get(bulkUpdateActiveTab) || false

    if (!containerImage.trim()) {
      setErrorMessage('Please enter a new ' + (containerTagOnly ? 'tag' : 'image') + ' for ' + bulkUpdateActiveTab + ' containers')
      return
    }

    setIsUpdating(true)
    setErrorMessage(null)

    try {
      // Build updates for all selected deployments, but only for containers matching the active tab type
      const updates: ImageUpdate[] = []
      const isSidecarTab = bulkUpdateActiveTab === 'sidecar'
      
      deployments.forEach((deployment) => {
        const key = `${deployment.namespace}/${deployment.name}`
        if (bulkUpdateSelections.has(key)) {
          deployment.containers.forEach((container) => {
            // Only update containers matching the active tab type (sidecar vs main)
            const isContainerSidecar = container.name.toLowerCase().includes('sidecar')
            if (isSidecarTab === isContainerSidecar) {
              // If tag-only mode, apply the tag to the base image
              const finalImage = containerTagOnly 
                ? applyTagOnlyUpdate(container.image, containerImage.trim())
                : containerImage.trim()
              
              updates.push({
                namespace: deployment.namespace,
                deployment: deployment.name,
                container: container.name,
                image: finalImage,
                originalImage: container.image,
              })
            }
          })
        }
      })

      const response = await fetch(`${apiUrl}/k8s/update-images`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ updates, source: 'ui-bulk' }),
      })

      // Check if response is ok before parsing JSON
      if (!response.ok) {
        const errorText = await response.text()
        let errorData
        try {
          errorData = JSON.parse(errorText)
        } catch {
          errorData = { message: errorText || `HTTP ${response.status}: ${response.statusText}` }
        }
        throw new Error(errorData.error || errorData.message || `HTTP ${response.status}: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.success) {
        // All updates succeeded
        setErrorMessage(`✅ Successfully updated ${data.updated || updates.length} container(s)`)
        setShowBulkUpdateWizard(false)
        setBulkUpdateSelections(new Set())
        setBulkUpdateImage('')
        setBulkUpdateTagOnly(false)
        setBulkUpdateActiveTab('')
        setBulkUpdateContainerImages(new Map())
        setBulkUpdateContainerTagOnly(new Map())
        setBulkUpdateStep('select')
        await loadData()
        setTimeout(() => setErrorMessage(null), 5000)
      } else if (data.updated && data.updated > 0) {
        // Partial success - some succeeded, some failed
        const errorDetails = data.errors && data.errors.length > 0
          ? data.errors.map((e: any) => `${e.deployment}/${e.container}: ${e.error}`).join('; ')
          : 'See details above'
        setErrorMessage(
          `⚠️ Partial update: ${data.updated} succeeded, ${data.failed || 0} failed. ${errorDetails}`
        )
        setShowBulkUpdateWizard(false)
        setBulkUpdateSelections(new Set())
        setBulkUpdateImage('')
        setBulkUpdateTagOnly(false)
        setBulkUpdateActiveTab('')
        setBulkUpdateContainerImages(new Map())
        setBulkUpdateContainerTagOnly(new Map())
        setBulkUpdateStep('select')
        await loadData()
        setTimeout(() => setErrorMessage(null), 8000)
      } else {
        // All updates failed
        const errorMsg = data.errors && data.errors.length > 0
          ? data.errors.map((e: any) => `${e.deployment}/${e.container}: ${e.error}`).join('; ')
          : data.error || data.message || 'Unknown error'
        setErrorMessage(`❌ Failed to update images: ${errorMsg}`)
        setTimeout(() => setErrorMessage(null), 10000)
      }
    } catch (error: any) {
      console.error('Error updating images:', error)
      setErrorMessage(`❌ Failed to update images: ${error.message || 'Network error. Please check if the API server is running and you are connected to the cluster.'}`)
      setTimeout(() => setErrorMessage(null), 10000)
    } finally {
      setIsUpdating(false)
    }
  }

  const handleScaleDeployment = async (namespace: string, name: string, replicas: number) => {
    setIsActioning(true)
    setErrorMessage(null)
    
    try {
      const response = await fetch(`${apiUrl}/k8s/deployments/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/scale`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ replicas }),
      })

      const data = await response.json()

      if (data.success) {
        setErrorMessage(`✅ ${data.message}`)
        setTimeout(() => setErrorMessage(null), 5000)
        setActionModal(null)
        // Reload deployments to reflect the change
        await loadData()
      } else {
        setErrorMessage(`❌ ${data.error || data.message || 'Failed to scale deployment'}`)
      }
    } catch (error: any) {
      setErrorMessage(`❌ Failed to scale deployment: ${error.message}`)
    } finally {
      setIsActioning(false)
    }
  }

  const handleRestartDeployment = async (namespace: string, name: string) => {
    setIsActioning(true)
    setErrorMessage(null)
    
    try {
      const response = await fetch(`${apiUrl}/k8s/deployments/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/restart`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const data = await response.json()

      if (data.success) {
        setErrorMessage(`✅ ${data.message}`)
        setTimeout(() => setErrorMessage(null), 5000)
        setActionModal(null)
        // Reload deployments to reflect the change
        await loadData()
      } else {
        setErrorMessage(`❌ ${data.error || data.message || 'Failed to restart deployment'}`)
      }
    } catch (error: any) {
      setErrorMessage(`❌ Failed to restart deployment: ${error.message}`)
    } finally {
      setIsActioning(false)
    }
  }

  const handleDeleteResource = async (resourceType: string, namespace: string, name: string) => {
    setIsActioning(true)
    setErrorMessage(null)

    try {
      // If deleting a deployment, save its spec first for potential restore
      if (resourceType === 'deployments') {
        const deployment = deployments.find(d => d.name === name && d.namespace === namespace)
        if (deployment) {
          setDeletedDeployments(prev => [...prev, {
            name: deployment.name,
            namespace: deployment.namespace,
            deletedAt: new Date().toISOString(),
            spec: deployment
          }])
        }
      }

      const response = await fetch(`${apiUrl}/k8s/${resourceType}/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const data = await response.json()

      if (data.success) {
        setErrorMessage(`✅ ${data.message}`)
        setTimeout(() => setErrorMessage(null), 5000)
        setActionModal(null)
        // Reload data to reflect the deletion
        await loadData()
      } else {
        setErrorMessage(`❌ ${data.error || data.message || 'Failed to delete resource'}`)
      }
    } catch (error: any) {
      setErrorMessage(`❌ Failed to delete resource: ${error.message}`)
    } finally {
      setIsActioning(false)
    }
  }

  // Handle pod selection toggle
  const handlePodSelect = (podKey: string) => {
    setSelectedPods(prev => {
      const newSet = new Set(prev)
      if (newSet.has(podKey)) {
        newSet.delete(podKey)
      } else {
        newSet.add(podKey)
      }
      return newSet
    })
  }

  // Handle select all pods
  const handleSelectAllPods = () => {
    if (selectedPods.size === pods.length) {
      setSelectedPods(new Set())
    } else {
      setSelectedPods(new Set(pods.map(p => `${p.namespace}/${p.name}`)))
    }
  }

  // Handle bulk delete pods
  const handleBulkDeletePods = async () => {
    if (selectedPods.size === 0) return

    if (!confirm(`Are you sure you want to delete ${selectedPods.size} pod(s)? This action cannot be undone.`)) {
      return
    }

    setIsDeletingPods(true)
    setErrorMessage(null)

    let successCount = 0
    let failCount = 0

    for (const podKey of selectedPods) {
      const [namespace, name] = podKey.split('/')
      try {
        const response = await fetch(`${apiUrl}/k8s/pods/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`, {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
        })
        const data = await response.json()
        if (data.success) {
          successCount++
        } else {
          failCount++
        }
      } catch {
        failCount++
      }
    }

    setSelectedPods(new Set())
    setIsDeletingPods(false)

    if (failCount === 0) {
      setErrorMessage(`✅ Successfully deleted ${successCount} pod(s)`)
    } else {
      setErrorMessage(`⚠️ Deleted ${successCount} pod(s), failed to delete ${failCount} pod(s)`)
    }
    setTimeout(() => setErrorMessage(null), 5000)
    await loadData()
  }

  // Handle restore deleted deployment
  const handleRestoreDeployment = async (deletedDeployment: { name: string; namespace: string; deletedAt: string; spec: any }) => {
    if (!confirm(`Are you sure you want to restore deployment "${deletedDeployment.name}" in namespace "${deletedDeployment.namespace}"?`)) {
      return
    }

    setIsActioning(true)
    setErrorMessage(null)

    try {
      // Create deployment from saved spec
      const response = await fetch(`${apiUrl}/k8s/deployments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          namespace: deletedDeployment.namespace,
          name: deletedDeployment.name,
          spec: deletedDeployment.spec
        }),
      })

      const data = await response.json()

      if (data.success) {
        // Remove from deleted deployments list
        setDeletedDeployments(prev => prev.filter(d =>
          !(d.name === deletedDeployment.name && d.namespace === deletedDeployment.namespace && d.deletedAt === deletedDeployment.deletedAt)
        ))
        setErrorMessage(`✅ Successfully restored deployment "${deletedDeployment.name}"`)
        setTimeout(() => setErrorMessage(null), 5000)
        await loadData()
      } else {
        setErrorMessage(`❌ Failed to restore deployment: ${data.error || data.message}`)
      }
    } catch (error: any) {
      setErrorMessage(`❌ Failed to restore deployment: ${error.message}`)
    } finally {
      setIsActioning(false)
    }
  }

  // Handle clear deleted deployment from history
  const handleClearDeletedDeployment = (deletedDeployment: { name: string; namespace: string; deletedAt: string; spec: any }) => {
    setDeletedDeployments(prev => prev.filter(d =>
      !(d.name === deletedDeployment.name && d.namespace === deletedDeployment.namespace && d.deletedAt === deletedDeployment.deletedAt)
    ))
  }

  // Auto-connect on component mount (using ServiceAccount)
  useEffect(() => {
    if (apiUrl && !isConnected) {
      loadNamespaces(true);
    }
  }, [apiUrl]);

  // Get docker image tag from portal deployment for build version
  const portalDeployment = deployments.find(d => d.name.toLowerCase().includes('portal'))
  const dockerImageTag = portalDeployment && portalDeployment.containers?.length > 0
    ? portalDeployment.containers[0].image.split(':')[1] || 'latest'
    : (deployments.length > 0 && deployments[0].containers?.length > 0
        ? deployments[0].containers[0].image.split(':')[1] || 'latest'
        : 'latest')

  // ─── Helper: time ago ───
  const timeAgo = (dateStr: string) => {
    if (!dateStr) return '-'
    const now = new Date()
    const date = new Date(dateStr)
    const seconds = Math.floor((now.getTime() - date.getTime()) / 1000)
    if (seconds < 0) return 'just now'
    if (seconds < 60) return `${seconds}s ago`
    const minutes = Math.floor(seconds / 60)
    if (minutes < 60) return `${minutes}m ago`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours}h ago`
    const days = Math.floor(hours / 24)
    return `${days}d ago`
  }

  // ─── Fetch audit logs for overview ───
  useEffect(() => {
    if (activeResourceTab === 'overview' && isConnected && apiUrl) {
      fetch(`${apiUrl}/audit/logs?limit=10`)
        .then(res => res.json())
        .then(data => {
          if (data.success) setAuditLogs(data.logs || [])
        })
        .catch(err => console.warn('Failed to fetch audit logs:', err))
    }
  }, [activeResourceTab, isConnected, apiUrl])

  // ─── Fetch pod for Describe modal ───
  useEffect(() => {
    if (!describePod || !apiUrl) {
      setDescribePodContent(null)
      setDescribePodError(null)
      return
    }
    let cancelled = false
    setDescribePodLoading(true)
    setDescribePodError(null)
    setDescribePodContent(null)
    fetch(`${apiUrl}/k8s/pods/${encodeURIComponent(describePod.namespace)}/${encodeURIComponent(describePod.name)}`, {
      headers: getAuthHeaders(),
    })
      .then(res => res.json())
      .then(data => {
        if (cancelled) return
        if (data.success && data.pod) {
          setDescribePodContent(JSON.stringify(data.pod, null, 2))
        } else {
          setDescribePodError(data.message || 'Failed to load pod')
        }
      })
      .catch(err => {
        if (!cancelled) setDescribePodError(err.message || 'Failed to fetch pod')
      })
      .finally(() => {
        if (!cancelled) setDescribePodLoading(false)
      })
    return () => { cancelled = true }
  }, [describePod, apiUrl])

  // ─── Global search keyboard shortcut (Cmd+K / Ctrl+K) ───
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setShowSearchModal(true)
        setSearchQuery('')
      }
      if (e.key === 'Escape' && showSearchModal) {
        setShowSearchModal(false)
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [showSearchModal])

  // ─── Search results computation ───
  const searchResults = useMemo(() => {
    if (!searchQuery.trim()) return []
    const q = searchQuery.toLowerCase()
    const results: Array<{ type: string; name: string; namespace: string; tabKey: string; resourceType: string }> = []
    deployments.filter(d => d.name.toLowerCase().includes(q)).forEach(d =>
      results.push({ type: 'Deployment', name: d.name, namespace: d.namespace, tabKey: 'deployments', resourceType: 'deployment' }))
    pods.filter(p => p.name.toLowerCase().includes(q)).forEach(p =>
      results.push({ type: 'Pod', name: p.name, namespace: p.namespace, tabKey: 'pods', resourceType: 'pod' }))
    services.filter(s => s.name.toLowerCase().includes(q)).forEach(s =>
      results.push({ type: 'Service', name: s.name, namespace: s.namespace, tabKey: 'services', resourceType: 'service' }))
    configmaps.filter(c => c.name?.toLowerCase().includes(q)).forEach(c =>
      results.push({ type: 'ConfigMap', name: c.name, namespace: c.namespace, tabKey: 'configmaps', resourceType: 'configmap' }))
    secrets.filter(s => s.name?.toLowerCase().includes(q)).forEach(s =>
      results.push({ type: 'Secret', name: s.name, namespace: s.namespace, tabKey: 'secrets', resourceType: 'secret' }))
    cronjobs.filter(c => c.name.toLowerCase().includes(q)).forEach(c =>
      results.push({ type: 'CronJob', name: c.name, namespace: c.namespace, tabKey: 'cronjobs', resourceType: 'cronjob' }))
    jobs.filter(j => j.name.toLowerCase().includes(q)).forEach(j =>
      results.push({ type: 'Job', name: j.name, namespace: j.namespace, tabKey: 'jobs', resourceType: 'job' }))
    ingresses.filter(i => i.name.toLowerCase().includes(q)).forEach(i =>
      results.push({ type: 'Ingress', name: i.name, namespace: i.namespace, tabKey: 'ingresses', resourceType: 'ingress' }))
    pvcs.filter(p => p.name.toLowerCase().includes(q)).forEach(p =>
      results.push({ type: 'PVC', name: p.name, namespace: p.namespace, tabKey: 'pvcs', resourceType: 'pvc' }))
    // Nodes
    nodes.filter((n: any) => (n.name || n.metadata?.name || '').toLowerCase().includes(q)).forEach((n: any) =>
      results.push({ type: 'Node', name: n.name || n.metadata?.name, namespace: '', tabKey: 'overview', resourceType: 'node' }))
    // Events
    events.filter((e: any) => (e.message || '').toLowerCase().includes(q) || (e.reason || '').toLowerCase().includes(q) || (e.involvedObject?.name || '').toLowerCase().includes(q)).forEach((e: any) =>
      results.push({ type: 'Event', name: `${e.involvedObject?.kind || ''}/${e.involvedObject?.name || ''} — ${e.reason || ''}`, namespace: e.namespace || '', tabKey: 'events', resourceType: 'event' }))
    // Databases from localStorage (connected database services)
    try {
      const savedDbs = localStorage.getItem('database_connections')
      if (savedDbs) {
        const dbConns = JSON.parse(savedDbs) as Array<{ name: string; type: string; host?: string; namespace?: string }>
        dbConns.filter(db => (db.name || '').toLowerCase().includes(q) || (db.type || '').toLowerCase().includes(q) || (db.host || '').toLowerCase().includes(q)).forEach(db =>
          results.push({ type: 'Database', name: `${db.name} (${db.type})`, namespace: db.namespace || '', tabKey: 'databases', resourceType: 'database' }))
      }
    } catch {}
    return results.slice(0, 50)
  }, [searchQuery, deployments, pods, services, configmaps, secrets, cronjobs, jobs, ingresses, pvcs, nodes, events])

  // ─── Notifications computation ───
  const notifications = useMemo(() => {
    const notifs: Array<{ type: 'error' | 'warning'; message: string; resource: string; namespace: string; timestamp: string }> = []
    // Pods with CrashLoopBackOff or OOMKilled
    pods.forEach(pod => {
      if (pod.issues && Array.isArray(pod.issues)) {
        pod.issues.forEach((issue: any) => {
          if (issue.reason === 'CrashLoopBackOff' || issue.reason === 'OOMKilled') {
            notifs.push({ type: 'error', message: `${issue.reason}: ${issue.message || pod.name}`, resource: pod.name, namespace: pod.namespace, timestamp: pod.startTime || '' })
          }
        })
      }
    })
    // Pods with any issues (hasIssues flag from API)
    pods.forEach(pod => {
      if (pod.hasIssues && (!pod.issues || pod.issues.length === 0)) {
        notifs.push({ type: 'warning', message: `Pod ${pod.name} has issues (status: ${pod.status})`, resource: pod.name, namespace: pod.namespace, timestamp: pod.startTime || '' })
      }
    })
    // Pods not in Running/Succeeded state
    pods.forEach(pod => {
      if (pod.status && pod.status !== 'Running' && pod.status !== 'Succeeded') {
        // Avoid duplicate if already caught by issues above
        const alreadyNotified = notifs.some(n => n.resource === pod.name && n.namespace === pod.namespace)
        if (!alreadyNotified) {
          notifs.push({ type: 'warning', message: `Pod ${pod.name} is ${pod.status}`, resource: pod.name, namespace: pod.namespace, timestamp: pod.startTime || pod.creationTimestamp || '' })
        }
      }
    })
    // Deployments with Stalled / ReplicaFailure / Unavailable / Degraded
    deployments.forEach(dep => {
      if (dep.deploymentStatus === 'Stalled' || dep.deploymentStatus === 'ReplicaFailure' || dep.deploymentStatus === 'Unavailable' || dep.deploymentStatus === 'Degraded') {
        notifs.push({ type: 'error', message: `Deployment ${dep.name} is ${dep.deploymentStatus}`, resource: dep.name, namespace: dep.namespace, timestamp: dep.creationTimestamp })
      }
    })
    // Warning events — check both lastTimestamp and eventTime, use 2-hour window
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000)
    events.forEach((event: any) => {
      if (event.type === 'Warning') {
        const eventTs = event.lastTimestamp || event.eventTime || event.firstTimestamp
        if (eventTs && new Date(eventTs) > twoHoursAgo) {
          notifs.push({ type: 'warning', message: `${event.reason}: ${(event.message || '').slice(0, 80)}`, resource: `${event.involvedObject?.kind || ''}/${event.involvedObject?.name || ''}`, namespace: event.namespace || '', timestamp: eventTs })
        }
      }
    })
    // Pods with high restart count (API returns "restarts" field, not "restartCount")
    pods.forEach(pod => {
      const restarts = (pod as any).restarts ?? (pod as any).restartCount ?? 0
      if (restarts > 5) {
        // Avoid duplicate
        const alreadyNotified = notifs.some(n => n.resource === pod.name && n.namespace === pod.namespace && n.message.includes('restarts'))
        if (!alreadyNotified) {
          notifs.push({ type: 'warning', message: `Pod ${pod.name} has ${restarts} restarts`, resource: pod.name, namespace: pod.namespace, timestamp: pod.startTime || '' })
        }
      }
    })
    return notifs.slice(0, 50)
  }, [pods, deployments, events])

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Left Sidebar - Fixed Dark Theme */}
      <div className="w-52 bg-[#1e2a3a] flex flex-col fixed left-0 top-0 bottom-0 z-40">
        {/* Logo/Brand Section */}
        <div className="p-4 border-b border-[#2d3d4f]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center">
              <Server className="w-5 h-5 text-white" />
            </div>
            <span className="text-white font-semibold text-lg">Klarity</span>
          </div>
        </div>

        {/* Project/Namespace Selector */}
        <div className="p-4 border-b border-[#2d3d4f]">
          <div className="text-[10px] text-gray-400 uppercase tracking-wider mb-1">NAMESPACE</div>
          <div className="text-white text-sm font-medium truncate px-2 py-1.5">
            {selectedNamespace || 'Connecting...'}
          </div>
        </div>

        {/* Navigation Menu */}
        <nav className="flex-1 overflow-y-auto py-4">
          {/* Dashboard Overview */}
          <div className="px-3 mb-2">
            <button
              onClick={() => setActiveResourceTab('overview')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeResourceTab === 'overview' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:bg-[#2d3d4f] hover:text-white'
              }`}
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <rect x="3" y="3" width="7" height="7" rx="1" />
                <rect x="14" y="3" width="7" height="7" rx="1" />
                <rect x="3" y="14" width="7" height="7" rx="1" />
                <rect x="14" y="14" width="7" height="7" rx="1" />
              </svg>
              Dashboard
            </button>
          </div>

          {/* Resources Section */}
          <div className="px-3 mb-2">
            <button
              onClick={() => {
                const el = document.getElementById('resources-menu')
                if (el) el.classList.toggle('hidden')
              }}
              className="w-full flex items-center justify-between px-3 py-2 text-gray-400 hover:text-white text-xs font-semibold uppercase tracking-wider"
            >
              <span>Resources</span>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            <div id="resources-menu" className="mt-1 space-y-1">
              <button onClick={() => setActiveResourceTab('deployments')} className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'deployments' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <span className="flex items-center gap-3">
                  <Server className="w-4 h-4" />
                  Deployments
                </span>
                <span className="text-xs bg-[#3d4d5f] px-2 py-0.5 rounded">{deployments.length}</span>
              </button>
              <button onClick={() => setActiveResourceTab('pods')} className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'pods' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <span className="flex items-center gap-3">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><circle cx="15.5" cy="8.5" r="1.5"/><circle cx="8.5" cy="15.5" r="1.5"/><circle cx="15.5" cy="15.5" r="1.5"/></svg>
                  Pods
                </span>
                <span className="text-xs bg-[#3d4d5f] px-2 py-0.5 rounded">{pods.length}</span>
              </button>
              <button onClick={() => setActiveResourceTab('services')} className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'services' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <span className="flex items-center gap-3">
                  <Network className="w-4 h-4" />
                  Services
                </span>
                <span className="text-xs bg-[#3d4d5f] px-2 py-0.5 rounded">{services.length}</span>
              </button>
              <button onClick={() => setActiveResourceTab('configmaps')} className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'configmaps' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <span className="flex items-center gap-3">
                  <FileText className="w-4 h-4" />
                  ConfigMaps
                </span>
                <span className="text-xs bg-[#3d4d5f] px-2 py-0.5 rounded">{configmaps.length}</span>
              </button>
              <button onClick={() => setActiveResourceTab('secrets')} className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'secrets' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <span className="flex items-center gap-3">
                  <Lock className="w-4 h-4" />
                  Secrets
                </span>
                <span className="text-xs bg-[#3d4d5f] px-2 py-0.5 rounded">{secrets.length}</span>
              </button>
              <button onClick={() => setActiveResourceTab('cronjobs')} className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'cronjobs' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <span className="flex items-center gap-3">
                  <RotateCw className="w-4 h-4" />
                  CronJobs
                </span>
                <span className="text-xs bg-[#3d4d5f] px-2 py-0.5 rounded">{cronjobs.length}</span>
              </button>
              <button onClick={() => setActiveResourceTab('jobs')} className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'jobs' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <span className="flex items-center gap-3">
                  <CheckCircle className="w-4 h-4" />
                  Jobs
                </span>
                <span className="text-xs bg-[#3d4d5f] px-2 py-0.5 rounded">{jobs.length}</span>
              </button>
              <button onClick={() => setActiveResourceTab('events')} className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'events' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <span className="flex items-center gap-3">
                  <AlertTriangle className="w-4 h-4" />
                  Events
                </span>
                <span className="text-xs bg-[#3d4d5f] px-2 py-0.5 rounded">{events.length}</span>
              </button>
              <button onClick={() => setActiveResourceTab('ingresses')} className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'ingresses' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <span className="flex items-center gap-3">
                  <Network className="w-4 h-4" />
                  Ingresses
                </span>
                <span className="text-xs bg-[#3d4d5f] px-2 py-0.5 rounded">{ingresses.length}</span>
              </button>
              <button onClick={() => setActiveResourceTab('pvcs')} className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'pvcs' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <span className="flex items-center gap-3">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" /></svg>
                  PVCs
                </span>
                <span className="text-xs bg-[#3d4d5f] px-2 py-0.5 rounded">{pvcs.length}</span>
              </button>
            </div>
          </div>

          {/* Observability Section */}
          <div className="px-3 mb-2">
            <button
              onClick={() => {
                const el = document.getElementById('observability-menu')
                if (el) el.classList.toggle('hidden')
              }}
              className="w-full flex items-center justify-between px-3 py-2 text-gray-400 hover:text-white text-xs font-semibold uppercase tracking-wider"
            >
              <span>Observability</span>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            <div id="observability-menu" className="mt-1 space-y-1">
              <button onClick={() => setActiveResourceTab('flow-tracing')} className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'flow-tracing' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <Network className="w-4 h-4" />
                Flow Tracing
              </button>
            </div>
          </div>

          {/* Data Section - only when database feature enabled */}
          {enableDatabase && (
          <div className="px-3 mb-2">
            <button
              onClick={() => {
                const el = document.getElementById('data-menu')
                if (el) el.classList.toggle('hidden')
              }}
              className="w-full flex items-center justify-between px-3 py-2 text-gray-400 hover:text-white text-xs font-semibold uppercase tracking-wider"
            >
              <span>Data</span>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            <div id="data-menu" className="mt-1 space-y-1">
              {/* Databases sidebar item hidden */}
              {enableMongoDBWizard && (
                <button onClick={() => setActiveResourceTab('mongodb-wizard')} className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'mongodb-wizard' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3C7 3 4 7.5 4 12c0 3.5 1.5 6.5 4 8.5 0-3 1-5 4-6-3 1-4 4-4 4s1-4 4-5.5c-2 0-3.5.5-3.5.5S10 9 12 9s3.5 3.5 3.5 3.5S14 12 12 12c3 1.5 4 4.5 4 6 2.5-2 4-5 4-8.5C20 7.5 17 3 12 3z"/></svg>
                  MongoDB Compass
                </button>
              )}
              {enableAdminerWizard && (
                <button onClick={() => setActiveResourceTab('adminer-wizard')} className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'adminer-wizard' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
                  Adminer
                </button>
              )}
            </div>
          </div>
          )}

          {/* Tools Section */}
          <div className="px-3 mb-2">
            <button
              onClick={() => {
                const el = document.getElementById('tools-menu')
                if (el) el.classList.toggle('hidden')
              }}
              className="w-full flex items-center justify-between px-3 py-2 text-gray-400 hover:text-white text-xs font-semibold uppercase tracking-wider"
            >
              <span>Tools</span>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            <div id="tools-menu" className="mt-1 space-y-1">
              {enableImageChangeReport && (
              <button onClick={() => setActiveResourceTab('image-change-report')} className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'image-change-report' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <BarChart2 className="w-4 h-4" />
                Image change report
              </button>
              )}
              <button onClick={() => setActiveResourceTab('download-images')} className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all ${activeResourceTab === 'download-images' ? 'bg-[#2d3d4f] text-white' : 'text-gray-400 hover:bg-[#2d3d4f] hover:text-white'}`}>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Download Images
              </button>
            </div>
          </div>

        </nav>

        {/* Bottom Section */}
        <div className="p-4 border-t border-[#2d3d4f]">
          <div className="text-[10px] text-gray-500">Build version: <span className="text-gray-400 font-mono">{dockerImageTag}</span></div>
        </div>
      </div>

      {/* Main Content Area - Full width with left margin for fixed sidebar */}
      <div className="ml-52 min-h-screen">
        {/* Connection Banner - Only when not connected */}
        {!isConnected && (
          <div className="p-6">
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <div className="flex items-center gap-2 text-blue-700">
                <Loader2 className="w-5 h-5 animate-spin" />
                <span className="font-medium">Connecting to Kubernetes cluster via ServiceAccount...</span>
              </div>
            </div>
          </div>
        )}

        {/* Main Content */}
        {isConnected && (
          <div className="min-h-screen">
            {/* Header Banner - no overflow-hidden so notification dropdown is not clipped */}
            <div className="relative bg-gradient-to-r from-gray-700 to-gray-800 text-white">
              <div className="absolute inset-0 opacity-10">
                <svg className="w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
                  <defs>
                    <pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse">
                      <path d="M 10 0 L 0 0 0 10" fill="none" stroke="white" strokeWidth="0.5"/>
                    </pattern>
                  </defs>
                  <rect width="100" height="100" fill="url(#grid)" />
                </svg>
              </div>
              <div className="relative px-4 sm:px-6 py-4 sm:py-6 flex items-start justify-between">
                <div>
                  <h1 className="text-xl sm:text-2xl font-light mb-1">Welcome to Klarity</h1>
                  <p className="text-gray-300 text-xs sm:text-sm">Experience seamless Kubernetes management with powerful observability and control.</p>
                </div>
                <div className="flex items-center gap-2 z-10">
                  {/* Search Button */}
                  <button onClick={() => { setShowSearchModal(true); setSearchQuery('') }}
                    className="flex items-center gap-2 px-3 py-1.5 bg-white/10 hover:bg-white/20 rounded-lg text-sm text-gray-300 transition-colors">
                    <Search className="w-4 h-4" />
                    <span className="hidden sm:inline">Search</span>
                    <kbd className="hidden sm:inline px-1.5 py-0.5 text-[10px] bg-white/10 rounded font-mono">⌘K</kbd>
                  </button>
                  {/* Notification Bell */}
                  <div className="relative">
                    <button onClick={() => setShowNotificationPanel(!showNotificationPanel)}
                      className="relative p-2 bg-white/10 hover:bg-white/20 rounded-lg transition-colors">
                      <Bell className="w-5 h-5 text-white" />
                      {notifications.length > 0 && (
                        <span className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 text-white text-[10px] rounded-full flex items-center justify-center font-bold">
                          {notifications.length > 9 ? '9+' : notifications.length}
                        </span>
                      )}
                    </button>
                    {showNotificationPanel && (
                      <div className="absolute right-0 top-full mt-2 w-96 bg-white rounded-lg shadow-xl border border-gray-200 z-50 max-h-[400px] overflow-hidden">
                        <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between">
                          <h3 className="text-sm font-semibold text-gray-900">Notifications ({notifications.length})</h3>
                          <button onClick={() => setShowNotificationPanel(false)} className="text-gray-400 hover:text-gray-600"><X className="w-4 h-4" /></button>
                        </div>
                        <div className="overflow-y-auto max-h-[340px] divide-y divide-gray-100">
                          {notifications.length === 0 ? (
                            <div className="p-6 text-center text-sm text-gray-400">
                              <CheckCircle className="w-8 h-8 mx-auto mb-2 text-green-400" />
                              All clear! No issues detected.
                            </div>
                          ) : notifications.map((notif, idx) => {
                            const parts = (notif.resource || '').split('/')
                            const kind = parts.length > 1 ? parts[0] : 'Pod'
                            const name = parts.length > 1 ? parts[1] : notif.resource
                            const tabMap: Record<string, string> = { Pod: 'pods', Deployment: 'deployments', Service: 'services' }
                            const typeMap: Record<string, 'pod' | 'deployment' | 'service'> = { Pod: 'pod', Deployment: 'deployment', Service: 'service' }
                            const tab = tabMap[kind] || 'pods'
                            const resType = typeMap[kind] || 'pod'
                            return (
                              <div
                                key={idx}
                                className="px-4 py-3 hover:bg-gray-50 cursor-pointer"
                                onClick={() => {
                                  setShowNotificationPanel(false)
                                  setActiveResourceTab(tab as any)
                                  if (name) setSelectedResource({ type: resType, namespace: notif.namespace || selectedNamespace, name })
                                }}
                              >
                                <div className="flex items-start gap-2">
                                  <AlertTriangle className={`w-4 h-4 mt-0.5 flex-shrink-0 ${notif.type === 'error' ? 'text-red-500' : 'text-amber-500'}`} />
                                  <div className="flex-1 min-w-0">
                                    <p className="text-sm text-gray-900 truncate">{notif.message}</p>
                                    <p className="text-xs text-gray-500 mt-0.5">{notif.resource} · {timeAgo(notif.timestamp)}</p>
                                  </div>
                                </div>
                              </div>
                            )
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
              <div className="absolute right-0 top-0 h-full w-1/4 opacity-20">
                <svg viewBox="0 0 200 200" className="h-full w-full">
                  <circle cx="100" cy="100" r="80" fill="none" stroke="white" strokeWidth="0.5"/>
                  <circle cx="100" cy="100" r="60" fill="none" stroke="white" strokeWidth="0.5"/>
                  <circle cx="100" cy="100" r="40" fill="none" stroke="white" strokeWidth="0.5"/>
                </svg>
              </div>
            </div>

            {/* Tabs Navigation */}
            <div className="bg-white border-b border-gray-200 px-4 sm:px-6 overflow-x-auto">
              <div className="flex gap-4 sm:gap-6 min-w-max">
                <button
                  onClick={() => setActiveResourceTab('overview')}
                  className={`py-3 text-sm font-medium border-b-2 transition-colors ${
                    activeResourceTab === 'overview' || activeResourceTab === 'deployments' || activeResourceTab === 'pods' || activeResourceTab === 'services' || activeResourceTab === 'configmaps' || activeResourceTab === 'secrets' || activeResourceTab === 'cronjobs' || activeResourceTab === 'jobs' || activeResourceTab === 'events' || activeResourceTab === 'ingresses' || activeResourceTab === 'pvcs'
                      ? 'border-blue-600 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  Overview
                </button>
                <button
                  onClick={() => setActiveResourceTab('flow-tracing')}
                  className={`py-3 text-sm font-medium border-b-2 transition-colors ${
                    activeResourceTab === 'flow-tracing'
                      ? 'border-blue-600 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  Flow Tracing
                </button>
                {/* Databases tab hidden */}
                {enableMongoDBWizard && (
                <button
                  onClick={() => setActiveResourceTab('mongodb-wizard')}
                  className={`py-3 text-sm font-medium border-b-2 transition-colors ${
                    activeResourceTab === 'mongodb-wizard'
                      ? 'border-green-600 text-green-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  MongoDB Compass
                </button>
                )}
                {enableAdminerWizard && (
                <button
                  onClick={() => setActiveResourceTab('adminer-wizard')}
                  className={`py-3 text-sm font-medium border-b-2 transition-colors ${
                    activeResourceTab === 'adminer-wizard'
                      ? 'border-blue-600 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  Adminer
                </button>
                )}
                {enableImageChangeReport && (
                <button
                  onClick={() => setActiveResourceTab('image-change-report')}
                  className={`py-3 text-sm font-medium border-b-2 transition-colors ${
                    activeResourceTab === 'image-change-report'
                      ? 'border-blue-600 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  Image change report
                </button>
                )}
              </div>
            </div>

            {/* Content Area */}
            <div className="p-4 sm:p-6">
              {/* Quick Stats Cards + Resource Summary - hidden on Flow Tracing tab and all DB tabs */}
              {activeResourceTab !== 'flow-tracing' &&
               activeResourceTab !== 'databases' &&
               activeResourceTab !== 'mongodb-wizard' &&
               activeResourceTab !== 'adminer-wizard' && (
              <>
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
                <div className="flex items-center gap-3 flex-wrap">
                  <h2 className="text-lg sm:text-xl font-semibold text-gray-900">Cluster Resources</h2>
                  <span className="px-2.5 py-1 bg-emerald-100 text-emerald-700 text-xs font-medium rounded-full flex items-center gap-1">
                    <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full"></span>
                    Connected
                  </span>
                </div>
                <div className="flex items-center gap-3 flex-wrap">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={autoRefresh}
                      onChange={(e) => setAutoRefresh(e.target.checked)}
                      className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="text-sm text-gray-600">Auto-refresh</span>
                  </label>
                  {autoRefresh && (
                    <select
                      value={refreshInterval}
                      onChange={(e) => setRefreshInterval(Number(e.target.value))}
                      className="px-2 py-1 text-sm border border-gray-300 rounded text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    >
                      <option value={5}>5s</option>
                      <option value={10}>10s</option>
                      <option value={15}>15s</option>
                      <option value={30}>30s</option>
                      <option value={60}>60s</option>
                    </select>
                  )}
                  <button
                    onClick={() => loadData()}
                    disabled={isLoading}
                    className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
                  >
                    <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
                    Refresh
                  </button>
                </div>
              </div>

              {/* Compact Resource Summary Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 mb-4 sm:mb-6">
                <div onClick={() => setActiveResourceTab('deployments')} className={`bg-white rounded-lg border p-3 cursor-pointer transition-all hover:shadow ${activeResourceTab === 'deployments' ? 'border-blue-500 bg-blue-50' : 'border-gray-200'}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <Server className="w-4 h-4 text-blue-600" />
                    <span className="text-xs font-medium text-gray-600">Deployments</span>
                  </div>
                  <div className="text-xl font-bold text-gray-900 text-center">{deployments.length}</div>
                </div>
                <div onClick={() => setActiveResourceTab('pods')} className={`bg-white rounded-lg border p-3 cursor-pointer transition-all hover:shadow ${activeResourceTab === 'pods' ? 'border-blue-500 bg-blue-50' : 'border-gray-200'}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <svg className="w-4 h-4 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/></svg>
                    <span className="text-xs font-medium text-gray-600">Pods</span>
                  </div>
                  <div className="text-xl font-bold text-gray-900 text-center">{pods.length}</div>
                </div>
                <div onClick={() => setActiveResourceTab('services')} className={`bg-white rounded-lg border p-3 cursor-pointer transition-all hover:shadow ${activeResourceTab === 'services' ? 'border-blue-500 bg-blue-50' : 'border-gray-200'}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <Network className="w-4 h-4 text-purple-600" />
                    <span className="text-xs font-medium text-gray-600">Services</span>
                  </div>
                  <div className="text-xl font-bold text-gray-900 text-center">{services.length}</div>
                </div>
                <div onClick={() => setActiveResourceTab('cronjobs')} className={`bg-white rounded-lg border p-3 cursor-pointer transition-all hover:shadow ${activeResourceTab === 'cronjobs' ? 'border-blue-500 bg-blue-50' : 'border-gray-200'}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <RotateCw className="w-4 h-4 text-orange-600" />
                    <span className="text-xs font-medium text-gray-600">CronJobs</span>
                  </div>
                  <div className="text-xl font-bold text-gray-900 text-center">{cronjobs.length}</div>
                </div>
                <div onClick={() => setActiveResourceTab('jobs')} className={`bg-white rounded-lg border p-3 cursor-pointer transition-all hover:shadow ${activeResourceTab === 'jobs' ? 'border-blue-500 bg-blue-50' : 'border-gray-200'}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <CheckCircle className="w-4 h-4 text-teal-600" />
                    <span className="text-xs font-medium text-gray-600">Jobs</span>
                  </div>
                  <div className="text-xl font-bold text-gray-900 text-center">{jobs.length}</div>
                </div>
                <div onClick={() => setActiveResourceTab('events')} className={`bg-white rounded-lg border p-3 cursor-pointer transition-all hover:shadow ${activeResourceTab === 'events' ? 'border-blue-500 bg-blue-50' : 'border-gray-200'}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <AlertTriangle className="w-4 h-4 text-amber-600" />
                    <span className="text-xs font-medium text-gray-600">Events</span>
                  </div>
                  <div className="text-xl font-bold text-gray-900 text-center">{events.length}</div>
                </div>
                <div onClick={() => setActiveResourceTab('ingresses')} className={`bg-white rounded-lg border p-3 cursor-pointer transition-all hover:shadow ${activeResourceTab === 'ingresses' ? 'border-blue-500 bg-blue-50' : 'border-gray-200'}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <Network className="w-4 h-4 text-indigo-600" />
                    <span className="text-xs font-medium text-gray-600">Ingresses</span>
                  </div>
                  <div className="text-xl font-bold text-gray-900 text-center">{ingresses.length}</div>
                </div>
                <div onClick={() => setActiveResourceTab('pvcs')} className={`bg-white rounded-lg border p-3 cursor-pointer transition-all hover:shadow ${activeResourceTab === 'pvcs' ? 'border-blue-500 bg-blue-50' : 'border-gray-200'}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <svg className="w-4 h-4 text-pink-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" /></svg>
                    <span className="text-xs font-medium text-gray-600">PVCs</span>
                  </div>
                  <div className="text-xl font-bold text-gray-900 text-center">{pvcs.length}</div>
                </div>
              </div>
              </>
              )}

              {/* ═══ OVERVIEW TAB ═══ */}
              {activeResourceTab === 'overview' && (
                <div className="space-y-6">
                  {/* Health Summary Cards - clickable, numbers centered */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div onClick={() => setActiveResourceTab('deployments')} className="bg-white rounded-xl border border-gray-200 p-5 cursor-pointer transition-all hover:shadow-md hover:border-gray-300">
                      <div className="flex items-center gap-2 mb-2">
                        <Server className="w-5 h-5 text-blue-600" />
                        <span className="text-sm font-medium text-gray-600">Deployments</span>
                      </div>
                      <div className="text-3xl font-bold text-gray-900 text-center">{deployments.length}</div>
                      <div className="flex items-center justify-center gap-3 mt-2 flex-wrap">
                        <span className="text-xs px-2 py-0.5 bg-green-100 text-green-700 rounded-full">{deployments.filter(d => d.deploymentStatus === 'Ready').length} healthy</span>
                        {deployments.filter(d => d.hasIssues).length > 0 && <span className="text-xs px-2 py-0.5 bg-red-100 text-red-700 rounded-full">{deployments.filter(d => d.hasIssues).length} issues</span>}
                      </div>
                    </div>
                    <div onClick={() => setActiveResourceTab('pods')} className="bg-white rounded-xl border border-gray-200 p-5 cursor-pointer transition-all hover:shadow-md hover:border-gray-300">
                      <div className="flex items-center gap-2 mb-2">
                        <CheckCircle className="w-5 h-5 text-emerald-600" />
                        <span className="text-sm font-medium text-gray-600">Pods</span>
                      </div>
                      <div className="text-3xl font-bold text-gray-900 text-center">
                        <span className="text-emerald-600">{pods.filter((p: any) => p.status === 'Running' && p.ready !== false).length}</span>
                        <span className="text-lg text-gray-400 font-normal">/{pods.length}</span>
                      </div>
                      <div className="text-xs text-gray-500 mt-2 text-center">Running</div>
                    </div>
                    <div onClick={() => setActiveResourceTab('services')} className="bg-white rounded-xl border border-gray-200 p-5 cursor-pointer transition-all hover:shadow-md hover:border-gray-300">
                      <div className="flex items-center gap-2 mb-2">
                        <Network className="w-5 h-5 text-purple-600" />
                        <span className="text-sm font-medium text-gray-600">Services</span>
                      </div>
                      <div className="text-3xl font-bold text-gray-900 text-center">{services.length}</div>
                      <div className="text-xs text-gray-500 mt-2 text-center">Active in namespace</div>
                    </div>
                    <div onClick={() => setActiveResourceTab('events')} className="bg-white rounded-xl border border-gray-200 p-5 cursor-pointer transition-all hover:shadow-md hover:border-gray-300">
                      <div className="flex items-center gap-2 mb-2">
                        <AlertTriangle className="w-5 h-5 text-amber-600" />
                        <span className="text-sm font-medium text-gray-600">Warning Events</span>
                      </div>
                      <div className="text-3xl font-bold text-gray-900 text-center">{events.filter((e: any) => e.type === 'Warning').length}</div>
                      <div className="text-xs text-gray-500 mt-2 text-center">From cluster events</div>
                    </div>
                  </div>

                  {/* Deployment Status Distribution Bar */}
                  <div className="bg-white rounded-xl border border-gray-200 p-5">
                    <h3 className="text-sm font-semibold text-gray-700 mb-3">Deployment Health</h3>
                    {(() => {
                      const total = deployments.length || 1
                      const ready = deployments.filter(d => d.deploymentStatus === 'Ready').length
                      const progressing = deployments.filter(d => d.deploymentStatus === 'Progressing' || d.deploymentStatus === 'Updating').length
                      const stalled = deployments.filter(d => d.deploymentStatus === 'Stalled' || d.deploymentStatus === 'Degraded').length
                      const failed = deployments.filter(d => d.deploymentStatus === 'Unavailable' || d.deploymentStatus === 'ReplicaFailure').length
                      const other = total - ready - progressing - stalled - failed
                      return (
                        <div>
                          <div className="flex h-3 rounded-full overflow-hidden bg-gray-100">
                            {ready > 0 && <div className="bg-green-500 transition-all" style={{ width: `${(ready / total) * 100}%` }} title={`Ready: ${ready}`} />}
                            {progressing > 0 && <div className="bg-blue-500 transition-all" style={{ width: `${(progressing / total) * 100}%` }} title={`Progressing: ${progressing}`} />}
                            {stalled > 0 && <div className="bg-orange-500 transition-all" style={{ width: `${(stalled / total) * 100}%` }} title={`Stalled: ${stalled}`} />}
                            {failed > 0 && <div className="bg-red-500 transition-all" style={{ width: `${(failed / total) * 100}%` }} title={`Failed: ${failed}`} />}
                            {other > 0 && <div className="bg-gray-300 transition-all" style={{ width: `${(other / total) * 100}%` }} />}
                          </div>
                          <div className="flex flex-wrap gap-4 mt-3 text-xs text-gray-600">
                            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-green-500 rounded-full" />Ready: {ready}</span>
                            {progressing > 0 && <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-blue-500 rounded-full" />Progressing: {progressing}</span>}
                            {stalled > 0 && <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-orange-500 rounded-full" />Stalled: {stalled}</span>}
                            {failed > 0 && <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-red-500 rounded-full" />Failed: {failed}</span>}
                            {other > 0 && <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 bg-gray-300 rounded-full" />Other: {other}</span>}
                          </div>
                        </div>
                      )
                    })()}
                  </div>

                  {/* Unhealthy Resources */}
                  {(() => {
                    const unhealthyPods = pods.filter((p: any) => p.hasIssues || p.status !== 'Running' || p.ready === false)
                    if (unhealthyPods.length === 0) return (
                      <div className="bg-white rounded-xl border border-gray-200 p-5 text-center">
                        <CheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
                        <p className="text-sm text-gray-500">All pods are healthy and running.</p>
                      </div>
                    )
                    return (
                      <div className="bg-white rounded-xl border border-red-200">
                        <div className="px-5 py-3 border-b border-red-100 bg-red-50 rounded-t-xl">
                          <h3 className="text-sm font-semibold text-red-800">⚠ Unhealthy Pods ({unhealthyPods.length})</h3>
                        </div>
                        <div className="overflow-auto max-h-[320px]">
                          <table className="w-full">
                            <thead className="bg-gray-50 border-b border-gray-200 sticky top-0 z-10">
                              <tr>
                                <th className="px-5 py-2.5 text-left text-xs font-medium text-gray-500 uppercase">Pod</th>
                                <th className="px-5 py-2.5 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                                <th className="px-5 py-2.5 text-left text-xs font-medium text-gray-500 uppercase">Reason</th>
                                <th className="px-5 py-2.5 text-left text-xs font-medium text-gray-500 uppercase">Restarts</th>
                                <th className="px-5 py-2.5 text-left text-xs font-medium text-gray-500 uppercase">Age</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-100">
                              {unhealthyPods.map((pod: any) => (
                                <tr key={`${pod.namespace}/${pod.name}`} className="hover:bg-gray-50 cursor-pointer" onClick={() => { setActiveResourceTab('pods'); setSelectedResource({ type: 'pod', namespace: pod.namespace, name: pod.name }) }}>
                                  <td className="px-5 py-2.5 text-sm font-medium text-gray-900">{pod.name}</td>
                                  <td className="px-5 py-2.5"><span className={`px-2 py-0.5 text-xs font-semibold rounded-full ${pod.status === 'Running' ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800'}`}>{pod.status}</span></td>
                                  <td className="px-5 py-2.5 text-sm text-gray-600">{pod.issues?.[0]?.reason || (pod.ready === false ? 'Not Ready' : '-')}</td>
                                  <td className="px-5 py-2.5 text-sm text-gray-600">{pod.restartCount ?? 0}</td>
                                  <td className="px-5 py-2.5 text-sm text-gray-500">{timeAgo(pod.creationTimestamp || pod.startTime || '')}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )
                  })()}

                  {/* Recent Warning Events */}
                  {(() => {
                    const warningEvents = events.filter((e: any) => e.type === 'Warning')
                    if (warningEvents.length === 0) return null
                    const kindToTab: Record<string, string> = { Pod: 'pods', Deployment: 'deployments', Service: 'services', ReplicaSet: 'deployments', Node: 'overview' }
                    const kindToType: Record<string, 'pod' | 'deployment' | 'service' | null> = { Pod: 'pod', Deployment: 'deployment', Service: 'service', ReplicaSet: 'deployment', Node: null }
                    return (
                      <div className="bg-white rounded-xl border border-amber-200">
                        <div className="px-5 py-3 border-b border-amber-100 bg-amber-50 rounded-t-xl">
                          <h3 className="text-sm font-semibold text-amber-800">Recent Warning Events</h3>
                        </div>
                        <div className="overflow-auto max-h-[320px]">
                          <table className="w-full">
                            <thead className="bg-gray-50 border-b border-gray-200 sticky top-0 z-10">
                              <tr>
                                <th className="px-5 py-2.5 text-left text-xs font-medium text-gray-500 uppercase">When</th>
                                <th className="px-5 py-2.5 text-left text-xs font-medium text-gray-500 uppercase">Resource</th>
                                <th className="px-5 py-2.5 text-left text-xs font-medium text-gray-500 uppercase">Reason</th>
                                <th className="px-5 py-2.5 text-left text-xs font-medium text-gray-500 uppercase">Message</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-100">
                              {warningEvents.map((event: any, idx: number) => {
                                const kind = event.involvedObject?.kind || ''
                                const name = event.involvedObject?.name || ''
                                const tab = kindToTab[kind]
                                const resType = kindToType[kind]
                                const ns = event.involvedObject?.namespace || event.metadata?.namespace || selectedNamespace || ''
                                return (
                                  <tr
                                    key={event.uid || event.metadata?.uid || idx}
                                    className="hover:bg-gray-50 cursor-pointer"
                                    onClick={() => {
                                      if (tab) setActiveResourceTab(tab as any)
                                      if (resType && name) setSelectedResource({ type: resType, namespace: ns || selectedNamespace, name })
                                      if (tab === 'overview' && kind === 'Node') setSelectedResource(null)
                                    }}
                                  >
                                    <td className="px-5 py-2.5 text-sm text-gray-500 whitespace-nowrap">{timeAgo(event.lastTimestamp || event.eventTime || '')}</td>
                                    <td className="px-5 py-2.5 text-sm font-medium text-blue-600 underline decoration-blue-600/50">{event.involvedObject?.kind}/{event.involvedObject?.name}</td>
                                    <td className="px-5 py-2.5"><span className="px-2 py-0.5 text-xs font-medium bg-amber-100 text-amber-800 rounded">{event.reason}</span></td>
                                    <td className="px-5 py-2.5 text-sm text-gray-600 max-w-md truncate" title={event.message}>{event.message}</td>
                                  </tr>
                                )
                              })}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )
                  })()}

                  {/* Recent Activity from Audit Logs */}
                  <div className="bg-white rounded-xl border border-gray-200">
                    <div className="px-5 py-3 border-b border-gray-200">
                      <h3 className="text-sm font-semibold text-gray-700">Recent Activity</h3>
                    </div>
                    {auditLogs.length === 0 ? (
                      <div className="p-6 text-center text-sm text-gray-400">No recent activity recorded.</div>
                    ) : (
                      <div className="divide-y divide-gray-100 overflow-y-auto max-h-[320px]">
                        {auditLogs.map((log: any, idx: number) => {
                          const resourceType = (log.resourceType || '').toLowerCase()
                          const tabMap: Record<string, string> = { deployments: 'deployments', pods: 'pods', services: 'services', configmaps: 'configmaps', secrets: 'secrets', cronjobs: 'cronjobs', jobs: 'jobs', ingresses: 'ingresses', pvcs: 'pvcs', namespaces: 'overview' }
                          const typeMap: Record<string, 'deployment' | 'pod' | 'service' | 'configmap' | 'secret' | 'cronjob' | 'job' | 'ingress' | 'pvc' | null> = { deployments: 'deployment', pods: 'pod', services: 'service', configmaps: 'configmap', secrets: 'secret', cronjobs: 'cronjob', jobs: 'job', ingresses: 'ingress', pvcs: 'pvc', namespaces: null }
                          const tab = tabMap[resourceType]
                          const resType = typeMap[resourceType]
                          const ns = log.namespace || selectedNamespace || ''
                          return (
                            <div
                              key={log.id || idx}
                              className="px-5 py-3 flex items-center justify-between text-sm hover:bg-gray-50 cursor-pointer"
                              onClick={() => {
                                if (tab) setActiveResourceTab(tab as any)
                                if (resType && log.resourceName) setSelectedResource({ type: resType, namespace: ns, name: log.resourceName })
                              }}
                            >
                              <div className="flex items-center gap-3">
                                <span className={`w-2 h-2 rounded-full ${log.action === 'DELETE' ? 'bg-red-500' : log.action === 'IMAGE_UPDATE' ? 'bg-blue-500' : log.action === 'SCALE' ? 'bg-purple-500' : log.action === 'RESTART' ? 'bg-orange-500' : 'bg-green-500'}`} />
                                <span className="text-gray-500 font-medium">{log.user || 'system'}</span>
                                <span className="px-1.5 py-0.5 text-xs bg-gray-100 text-gray-600 rounded">{log.action}</span>
                                <span className="text-gray-700 text-blue-600 underline decoration-blue-600/50">{log.resourceType}/{log.resourceName}</span>
                              </div>
                              <span className="text-gray-400 text-xs whitespace-nowrap">{timeAgo(log.timestamp)}</span>
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Bulk Update Controls - Show for deployments */}
              {activeResourceTab === 'deployments' && deployments.length > 0 && (
                <div className="bg-white rounded-lg border border-gray-200 p-3 sm:p-4 mb-4">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                    <div className="flex items-center gap-4 sm:gap-6 flex-wrap">
                      <span className="text-sm font-medium text-gray-700">Update Mode:</span>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="radio"
                          name="updateMode"
                          value="selective"
                          checked={updateMode === 'selective'}
                          onChange={(e) => setUpdateMode(e.target.value as 'selective' | 'bulk')}
                          className="w-4 h-4 text-blue-600"
                        />
                        <span className="text-sm text-gray-700">Selective</span>
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="radio"
                          name="updateMode"
                          value="bulk"
                          checked={updateMode === 'bulk'}
                          onChange={(e) => setUpdateMode(e.target.value as 'selective' | 'bulk')}
                          className="w-4 h-4 text-blue-600"
                        />
                        <span className="text-sm text-gray-700">Bulk Update</span>
                      </label>
                    </div>
                    {updateMode === 'bulk' && (
                      <button
                        onClick={() => {
                          setShowBulkUpdateWizard(true)
                          setBulkUpdateStep('select')
                          setBulkUpdateActiveTab('')
                          setBulkUpdateContainerImages(new Map())
                          setBulkUpdateContainerTagOnly(new Map())
                          if (bulkUpdateSelections.size === 0) {
                            const allKeys = new Set(deployments.map(d => `${d.namespace}/${d.name}`))
                            setBulkUpdateSelections(allKeys)
                          }
                        }}
                        className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
                      >
                        <RefreshCw className="w-4 h-4" />
                        Open Bulk Update Wizard
                      </button>
                    )}
                  </div>
                  {imageUpdates.size > 0 && (
                    <div className="mt-4 pt-4 border-t border-gray-200 flex items-center justify-between">
                      <span className="text-sm text-gray-600">{imageUpdates.size} image(s) pending update</span>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setShowImageComparison(true)}
                          className="px-3 py-1.5 border border-blue-200 text-blue-700 rounded text-sm hover:bg-blue-50"
                        >
                          <Eye className="w-4 h-4 inline mr-1" />
                          Review
                        </button>
                        <button
                          onClick={handleUpdateImages}
                          disabled={isUpdating}
                          className="px-3 py-1.5 bg-green-600 text-white rounded text-sm hover:bg-green-700 disabled:opacity-50"
                        >
                          {isUpdating ? <Loader2 className="w-4 h-4 inline animate-spin mr-1" /> : <Save className="w-4 h-4 inline mr-1" />}
                          Apply Updates
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Resource Details Section */}
                  {/* Detailed Resource View */}
                  <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
                {/* Deployments Tab Content */}
                {activeResourceTab === 'deployments' && (
                  <div className="min-w-0 p-3 sm:p-4">
                    {/* Deleted Deployments Restore Section - only when deployment delete enabled */}
                    {enableDeploymentDelete && deletedDeployments.length > 0 && (
                      <div className="mb-4">
                        <button
                          onClick={() => setShowDeletedDeployments(!showDeletedDeployments)}
                          className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-amber-700 bg-amber-50 hover:bg-amber-100 rounded-lg border border-amber-200 transition-colors"
                        >
                          <RotateCcw className="w-4 h-4" />
                          Restore Deleted Deployments ({deletedDeployments.length})
                          <ChevronDown className={`w-4 h-4 transition-transform ${showDeletedDeployments ? 'rotate-180' : ''}`} />
                        </button>
                        {showDeletedDeployments && (
                          <div className="mt-2 bg-amber-50 border border-amber-200 rounded-lg overflow-hidden">
                            <div className="px-4 py-2 bg-amber-100 border-b border-amber-200">
                              <span className="text-sm font-medium text-amber-800">Recently Deleted Deployments</span>
                              <span className="ml-2 text-xs text-amber-600">(Session only - will be lost on page refresh)</span>
                            </div>
                            <div className="divide-y divide-amber-200">
                              {deletedDeployments.map((deleted, idx) => (
                                <div key={`${deleted.namespace}-${deleted.name}-${idx}`} className="px-4 py-3 flex items-center justify-between hover:bg-amber-100/50">
                                  <div>
                                    <div className="font-medium text-gray-900">{deleted.name}</div>
                                    <div className="text-xs text-gray-500">
                                      Namespace: {deleted.namespace} | Deleted: {new Date(deleted.deletedAt).toLocaleString()}
                                    </div>
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <button
                                      onClick={() => handleRestoreDeployment(deleted)}
                                      disabled={isActioning}
                                      className="px-3 py-1.5 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50 flex items-center gap-1 transition-colors"
                                    >
                                      <RotateCcw className="w-3.5 h-3.5" />
                                      Restore
                                    </button>
                                    <button
                                      onClick={() => handleClearDeletedDeployment(deleted)}
                                      className="px-3 py-1.5 text-sm text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded transition-colors"
                                      title="Remove from restore list"
                                    >
                                      <X className="w-4 h-4" />
                                    </button>
                                  </div>
                                </div>
                              ))}
                            </div>
                            <div className="px-4 py-2 bg-amber-100/50 border-t border-amber-200">
                              <button
                                onClick={() => setDeletedDeployments([])}
                                className="text-xs text-amber-700 hover:text-amber-900 underline"
                              >
                                Clear all from restore list
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                    {isLoading ? (
            <div className="p-16 text-center">
              <div className="w-12 h-12 mx-auto rounded-full bg-blue-50 flex items-center justify-center mb-4">
                <Loader2 className="w-6 h-6 animate-spin text-blue-600" />
              </div>
              <p className="text-gray-500 font-medium">Loading deployments...</p>
            </div>
          ) : deployments.length === 0 ? (
            <div className="p-16 text-center">
              <div className="w-16 h-16 mx-auto rounded-full bg-gray-100 flex items-center justify-center mb-4">
                <Server className="w-8 h-8 text-gray-400" />
              </div>
              <p className="text-gray-500 font-medium">No deployments found</p>
              <p className="text-gray-400 text-sm mt-1">{selectedNamespace === 'all' ? 'in any namespace' : `in namespace "${selectedNamespace}"`}</p>
            </div>
          ) : (
            <div className="w-full overflow-x-auto rounded-lg border border-gray-200 shadow-sm">
              <table className="w-full min-w-[800px]">
                <thead>
                  <tr className="bg-slate-50 border-b border-gray-200">
                    {updateMode === 'selective' && (
                      <th className="w-10 px-3 py-3 text-left text-[10px] font-semibold text-gray-600 uppercase tracking-wider">
                        <input
                          type="checkbox"
                          checked={
                            deployments.length > 0 &&
                            deployments.every((d) =>
                              selectedDeployments.has(`${d.namespace}/${d.name}`)
                            )
                          }
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedDeployments(
                                new Set(
                                  deployments.map((d) => `${d.namespace}/${d.name}`)
                                )
                              )
                            } else {
                              setSelectedDeployments(new Set())
                            }
                          }}
                          className="w-4 h-4 rounded border-gray-300 bg-white text-blue-600 focus:ring-blue-500"
                        />
                      </th>
                    )}
                    {selectedNamespace === 'all' && (
                      <th className="w-24 px-3 py-3 text-left text-[10px] font-semibold text-gray-600 uppercase tracking-wider">
                        Namespace
                      </th>
                    )}
                    <th className="px-3 py-3 text-left text-[10px] font-semibold text-gray-600 uppercase tracking-wider">
                      Deployment
                    </th>
                    <th className="px-3 py-3 text-left text-[10px] font-semibold text-gray-600 uppercase tracking-wider">
                      Container
                    </th>
                    <th className="min-w-[220px] max-w-[320px] px-3 py-3 text-left text-[10px] font-semibold text-gray-600 uppercase tracking-wider">
                      Current Image
                    </th>
                    <th className="min-w-[220px] max-w-[320px] px-3 py-3 text-left text-[10px] font-semibold text-gray-600 uppercase tracking-wider">
                      New Image
                    </th>
                    <th className="w-28 px-3 py-3 text-left text-[10px] font-semibold text-gray-600 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {deployments.map((deployment) =>
                    (deployment.containers || []).map((container, idx) => {
                      const key = `${deployment.namespace}/${deployment.name}/${container.name}`
                      const update = imageUpdates.get(key)
                      const isSelected = selectedDeployments.has(
                        `${deployment.namespace}/${deployment.name}`
                      )

                      return (
                        <tr
                          key={`${deployment.name}-${container.name}-${idx}`}
                          className={`${update ? 'bg-blue-50' : ''} hover:bg-slate-50 transition-colors`}
                        >
                          {updateMode === 'selective' && idx === 0 && (
                            <td
                              rowSpan={deployment.containers.length}
                              className="px-3 py-3 align-top"
                            >
                              <input
                                type="checkbox"
                                checked={isSelected}
                                onChange={() =>
                                  toggleDeploymentSelection(deployment.namespace, deployment.name)
                                }
                                className="w-4 h-4 rounded border-gray-300 bg-white text-blue-600"
                              />
                            </td>
                          )}
                          {selectedNamespace === 'all' && idx === 0 && (
                            <td
                              rowSpan={deployment.containers.length}
                              className="px-3 py-3 align-top text-xs font-medium text-gray-500 truncate max-w-[96px]"
                              title={deployment.namespace}
                            >
                              {deployment.namespace}
                            </td>
                          )}
                          {idx === 0 && (
                            <td
                              rowSpan={deployment.containers.length}
                              className="px-3 py-3 align-top"
                            >
                              <div className="flex flex-col gap-1">
                                <span className="text-sm font-medium text-gray-900">{deployment.name}</span>
                                <div className="flex items-center gap-2">
                                {/* Status indicator based on deploymentStatus */}
                                {deployment.deploymentStatus === 'Ready' ? (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-100 text-emerald-700">
                                    <span className="w-1.5 h-1.5 mr-1 rounded-full bg-emerald-500"></span>
                                    Ready
                                  </span>
                                ) : deployment.deploymentStatus === 'Progressing' || deployment.deploymentStatus === 'Updating' ? (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-100 text-blue-700">
                                    <span className="w-1.5 h-1.5 mr-1 rounded-full bg-blue-500 animate-pulse"></span>
                                    {deployment.deploymentStatus}
                                  </span>
                                ) : deployment.deploymentStatus === 'Stalled' ? (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-orange-100 text-orange-700">
                                    <span className="w-1.5 h-1.5 mr-1 rounded-full bg-orange-500"></span>
                                    Stalled
                                  </span>
                                ) : deployment.deploymentStatus === 'ReplicaFailure' || deployment.deploymentStatus === 'Unavailable' ? (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-red-100 text-red-700">
                                    <span className="w-1.5 h-1.5 mr-1 rounded-full bg-red-500 animate-pulse"></span>
                                    {deployment.deploymentStatus === 'ReplicaFailure' ? 'Failed' : 'Unavailable'}
                                  </span>
                                ) : deployment.deploymentStatus === 'Degraded' ? (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-yellow-100 text-yellow-700">
                                    <span className="w-1.5 h-1.5 mr-1 rounded-full bg-yellow-500 animate-pulse"></span>
                                    Degraded
                                  </span>
                                ) : deployment.deploymentStatus === 'ScaledToZero' ? (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-gray-100 text-gray-600">
                                    <span className="w-1.5 h-1.5 mr-1 rounded-full bg-gray-500"></span>
                                    Scaled to 0
                                  </span>
                                ) : deployment.readyReplicas === deployment.replicas && deployment.replicas > 0 ? (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-100 text-emerald-700">
                                    <span className="w-1.5 h-1.5 mr-1 rounded-full bg-emerald-500"></span>
                                    Ready
                                  </span>
                                ) : deployment.readyReplicas > 0 ? (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-yellow-100 text-yellow-700">
                                    <span className="w-1.5 h-1.5 mr-1 rounded-full bg-yellow-500 animate-pulse"></span>
                                    Partial
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-red-100 text-red-700">
                                    <span className="w-1.5 h-1.5 mr-1 rounded-full bg-red-500 animate-pulse"></span>
                                    Not Ready
                                  </span>
                                )}
                                <span className="text-[10px] text-gray-500">{deployment.readyReplicas}/{deployment.replicas}</span>
                                </div>
                              </div>
                                {/* Warning triangle for deployments with issues */}
                                {deployment.hasIssues && (
                                  <div className="relative">
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        const depKey = `${deployment.namespace}-${deployment.name}`
                                        setExpandedDeploymentIssues(expandedDeploymentIssues === depKey ? null : depKey)
                                      }}
                                      className="p-1 text-amber-500 hover:text-amber-600 hover:bg-amber-50 rounded transition-colors"
                                      title="View deployment issues"
                                    >
                                      <AlertTriangle className="w-4 h-4" />
                                    </button>
                                    {expandedDeploymentIssues === `${deployment.namespace}-${deployment.name}` && (
                                      <div className="absolute z-50 left-0 top-8 w-80 bg-white border border-gray-200 rounded-lg shadow-xl p-3 text-xs">
                                        <div className="flex items-center justify-between mb-2 pb-2 border-b border-gray-100">
                                          <span className="font-semibold text-gray-900 flex items-center gap-1">
                                            <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                                            Deployment Issues ({deployment.issues?.length || 0})
                                          </span>
                                          <button
                                            onClick={(e) => {
                                              e.stopPropagation()
                                              setExpandedDeploymentIssues(null)
                                            }}
                                            className="text-gray-400 hover:text-gray-600"
                                          >
                                            ×
                                          </button>
                                        </div>
                                        <div className="space-y-2 max-h-64 overflow-y-auto">
                                          {deployment.statusReason && (
                                            <div className={`p-2 rounded ${
                                              deployment.deploymentStatus === 'Stalled' || deployment.deploymentStatus === 'ReplicaFailure'
                                                ? 'bg-red-50 border border-red-200'
                                                : 'bg-amber-50 border border-amber-200'
                                            }`}>
                                              <div className="font-medium text-gray-900">{deployment.statusReason}</div>
                                              {deployment.statusMessage && (
                                                <div className="mt-1 text-gray-600 break-words">
                                                  {deployment.statusMessage.length > 200
                                                    ? `${deployment.statusMessage.substring(0, 200)}...`
                                                    : deployment.statusMessage}
                                                </div>
                                              )}
                                            </div>
                                          )}
                                          {deployment.issues && deployment.issues.length > 0 && deployment.issues.map((issue, issueIdx) => (
                                            <div key={issueIdx} className="p-2 rounded bg-amber-50 border border-amber-200">
                                              <div className="flex items-start gap-2">
                                                <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-purple-100 text-purple-700">
                                                  {issue.conditionType}
                                                </span>
                                                <div className="flex-1 min-w-0">
                                                  <div className="font-medium text-gray-900">{issue.reason}</div>
                                                  {issue.message && (
                                                    <div className="mt-1 text-gray-600 break-words">
                                                      {issue.message.length > 150
                                                        ? `${issue.message.substring(0, 150)}...`
                                                        : issue.message}
                                                    </div>
                                                  )}
                                                </div>
                                              </div>
                                            </div>
                                          ))}
                                        </div>
                                        {/* Show deployment conditions */}
                                        {deployment.conditions && deployment.conditions.some(c => c.status === 'False') && (
                                          <div className="mt-3 pt-2 border-t border-gray-100">
                                            <div className="text-[10px] font-semibold text-gray-700 mb-1">Conditions:</div>
                                            <div className="space-y-1">
                                              {deployment.conditions.filter(c => c.status === 'False').map((cond, condIdx) => (
                                                <div key={condIdx} className="flex items-center gap-1 text-[10px]">
                                                  <XCircle className="w-3 h-3 text-red-500" />
                                                  <span className="font-medium">{cond.type}:</span>
                                                  <span className="text-gray-600">{cond.reason || 'Unknown'}</span>
                                                </div>
                                              ))}
                                            </div>
                                          </div>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                )}
                            </td>
                          )}
                          <td className="px-3 py-3 text-xs text-gray-600" title={container.name}>
                            {container.name}
                          </td>
                          <td className="px-3 py-3 text-gray-600 font-mono text-[11px] min-w-[220px] max-w-[320px]" title={container.image}>
                            <span className="block break-all">{container.image}</span>
                          </td>
                          <td className="px-3 py-3 min-w-[220px] max-w-[320px]">
                            <div className="flex items-center gap-2 min-w-0">
                            <input
                              type="text"
                              key={`${deployment.name}-${container.name}-${container.image}`}
                              value={update ? update.image : container.image}
                              onChange={(e) =>
                                handleImageChange(
                                  deployment.namespace,
                                  deployment.name,
                                  container.name,
                                  e.target.value,
                                  container.image
                                )
                              }
                              placeholder={container.image}
                              title={update ? update.image : container.image}
                              className="flex-1 min-w-0 px-2 py-1.5 bg-white border border-gray-300 rounded text-[11px] font-mono text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                            />
                              {update && update.image !== container.image && (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    const newImage = update?.image || container.image
                                    if (!newImage || newImage.trim() === '') {
                                      setErrorMessage('Please enter a valid image name')
                                      setTimeout(() => setErrorMessage(null), 2000)
                                      return
                                    }
                                    handleSaveSingleImage(
                                      deployment.namespace,
                                      deployment.name,
                                      container.name,
                                      newImage,
                                      container.image
                                    )
                                  }}
                                  disabled={isUpdating}
                                  className="px-2 py-1.5 bg-emerald-600 text-white text-[10px] rounded hover:bg-emerald-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1"
                                  title="Save"
                                >
                                  {isUpdating ? (
                                    <Loader2 className="w-3 h-3 animate-spin" />
                                  ) : (
                                    <Save className="w-3 h-3" />
                                  )}
                                </button>
                              )}
                            </div>
                          </td>
                          {idx === 0 && (
                            <td
                              rowSpan={deployment.containers.length}
                              className="px-3 py-3 align-top"
                            >
                              <div className="flex items-center gap-0.5">
                                <button
                                  onClick={() => setSelectedResource({ type: 'deployment', namespace: deployment.namespace, name: deployment.name })}
                                  className="p-1.5 text-blue-600 hover:text-blue-700 hover:bg-blue-50 rounded transition-colors"
                                  title="View details"
                                >
                                  <Eye className="w-3.5 h-3.5" />
                                </button>
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    setScaleReplicas(deployment.replicas)
                                    setActionModal({
                                      type: 'scale',
                                      resourceType: 'deployment',
                                      namespace: deployment.namespace,
                                      name: deployment.name,
                                      currentReplicas: deployment.replicas
                                    })
                                  }}
                                  className="p-1.5 text-green-600 hover:text-green-700 hover:bg-green-50 rounded transition-colors"
                                  title="Scale deployment"
                                >
                                  <Plus className="w-3.5 h-3.5" />
                                </button>
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    setActionModal({
                                      type: 'restart',
                                      resourceType: 'deployment',
                                      namespace: deployment.namespace,
                                      name: deployment.name
                                    })
                                  }}
                                  className="p-1.5 text-amber-600 hover:text-amber-700 hover:bg-amber-50 rounded transition-colors"
                                  title="Restart deployment"
                                >
                                  <RotateCw className="w-3.5 h-3.5" />
                                </button>
                                {enableDeploymentDelete && (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    setActionModal({
                                      type: 'delete',
                                      resourceType: 'deployments',
                                      namespace: deployment.namespace,
                                      name: deployment.name
                                    })
                                  }}
                                  className="p-1.5 text-red-600 hover:text-red-700 hover:bg-red-50 rounded transition-colors"
                                  title="Delete deployment"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                                )}
                                <button
                                  onClick={() => {
                                    // Focus on first container image input for this deployment
                                    const firstInput = document.querySelector(
                                      `input[placeholder="${deployment.containers[0]?.image}"]`
                                    ) as HTMLInputElement
                                    firstInput?.focus()
                                  }}
                                  className="p-2 text-purple-600 hover:text-purple-800 hover:bg-purple-50 rounded transition-colors"
                                  title="Edit deployment images"
                                >
                                  <Edit className="w-4 h-4" />
                                </button>
                              </div>
                            </td>
                          )}
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          )}


                    {imageUpdates.size > 0 && (
                      <div className="px-6 py-4 border-t border-gray-200 bg-gray-50">
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-gray-600">
                            {imageUpdates.size} container image(s) pending update
                          </span>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => setShowImageComparison(true)}
                            className="flex items-center gap-2 px-4 py-2 border border-blue-200 text-blue-700 rounded-md hover:bg-blue-50 transition-colors text-sm"
                          >
                            <Eye className="w-4 h-4" />
                            Review changes
                          </button>
                          <button
                            onClick={handleUpdateImages}
                            disabled={isUpdating}
                            className="flex items-center gap-2 px-6 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors disabled:opacity-50"
                          >
                            {isUpdating ? (
                              <>
                                <Loader2 className="w-4 h-4 animate-spin" />
                                Updating...
                              </>
                            ) : (
                              <>
                                <Save className="w-4 h-4" />
                                Apply Updates ({imageUpdates.size})
                              </>
                            )}
                          </button>
                        </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Pods Tab Content */}
                {activeResourceTab === 'pods' && (
                  <div>
                    {/* Bulk Actions Bar */}
                    {selectedPods.size > 0 && (
                      <div className="px-4 py-3 bg-blue-50 border-b border-blue-200 flex items-center justify-between">
                        <span className="text-sm font-medium text-blue-800">
                          {selectedPods.size} pod(s) selected
                        </span>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => setSelectedPods(new Set())}
                            className="px-3 py-1.5 text-sm text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded transition-colors"
                          >
                            Clear Selection
                          </button>
                          <button
                            onClick={handleBulkDeletePods}
                            disabled={isDeletingPods}
                            className="px-4 py-1.5 bg-red-600 text-white text-sm rounded hover:bg-red-700 disabled:opacity-50 flex items-center gap-2 transition-colors"
                          >
                            {isDeletingPods ? (
                              <>
                                <Loader2 className="w-4 h-4 animate-spin" />
                                Deleting...
                              </>
                            ) : (
                              <>
                                <Trash2 className="w-4 h-4" />
                                Delete Selected
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    )}
                    {isLoading ? (
                      <div className="p-16 text-center">
                        <div className="w-12 h-12 mx-auto rounded-full bg-blue-50 flex items-center justify-center mb-4">
                          <Loader2 className="w-6 h-6 animate-spin text-blue-600" />
                        </div>
                        <p className="text-gray-500 font-medium">Loading pods...</p>
                      </div>
                    ) : pods.length === 0 ? (
                      <div className="p-16 text-center">
                        <div className="w-16 h-16 mx-auto rounded-full bg-gray-100 flex items-center justify-center mb-4">
                          <Server className="w-8 h-8 text-gray-400" />
                        </div>
                        <p className="text-gray-500 font-medium">No pods found</p>
                        <p className="text-gray-400 text-sm mt-1">{selectedNamespace === 'all' ? 'in any namespace' : `in namespace "${selectedNamespace}"`}</p>
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead>
                            <tr className="bg-slate-50/80">
                              <th className="px-3 py-3.5 text-left">
                                <input
                                  type="checkbox"
                                  checked={selectedPods.size === pods.length && pods.length > 0}
                                  onChange={handleSelectAllPods}
                                  className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500 cursor-pointer"
                                  title="Select all pods"
                                />
                              </th>
                              {selectedNamespace === 'all' && (
                                <th className="px-5 py-3.5 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">
                                  Namespace
                                </th>
                              )}
                              <th className="px-5 py-3.5 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">
                                Pod Name
                              </th>
                              <th className="px-5 py-3.5 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">
                                Status
                              </th>
                              <th className="px-5 py-3.5 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">
                                Node
                              </th>
                              <th className="px-5 py-3.5 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">
                                Pod IP
                              </th>
                              <th className="px-5 py-3.5 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">
                                Containers
                              </th>
                              <th className="px-5 py-3.5 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">
                                Restarts
                              </th>
                              <th className="px-5 py-3.5 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">
                                Actions
                              </th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-100">
                            {pods.map((pod) => {
                              const podKey = `${pod.namespace}/${pod.name}`
                              return (
                              <tr
                                key={`${pod.namespace}-${pod.name}`}
                                className={`hover:bg-blue-50/50 cursor-pointer transition-colors duration-150 group ${selectedPods.has(podKey) ? 'bg-blue-50' : ''}`}
                                onClick={() => setSelectedResource({ type: 'pod', namespace: pod.namespace, name: pod.name })}
                              >
                                <td className="px-3 py-4" onClick={(e) => e.stopPropagation()}>
                                  <input
                                    type="checkbox"
                                    checked={selectedPods.has(podKey)}
                                    onChange={() => handlePodSelect(podKey)}
                                    className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500 cursor-pointer"
                                  />
                                </td>
                                {selectedNamespace === 'all' && (
                                  <td className="px-6 py-4 text-sm font-medium text-gray-700">
                                    {pod.namespace}
                                  </td>
                                )}
                                <td className="px-6 py-4 text-sm font-medium text-gray-900">
                                  <div className="flex items-center gap-2">
                                    {pod.name}
                                    {pod.hasIssues && (
                                      <div className="relative">
                                        <button
                                          onClick={(e) => {
                                            e.stopPropagation()
                                            const podKey = `${pod.namespace}-${pod.name}`
                                            setExpandedPodIssues(expandedPodIssues === podKey ? null : podKey)
                                          }}
                                          className="p-1 text-amber-500 hover:text-amber-600 hover:bg-amber-50 rounded transition-colors"
                                          title="View pod issues"
                                        >
                                          <AlertTriangle className="w-4 h-4" />
                                        </button>
                                        {expandedPodIssues === `${pod.namespace}-${pod.name}` && (
                                          <div className="absolute z-50 left-0 top-8 w-80 bg-white border border-gray-200 rounded-lg shadow-xl p-3 text-xs">
                                            <div className="flex items-center justify-between mb-2 pb-2 border-b border-gray-100">
                                              <span className="font-semibold text-gray-900 flex items-center gap-1">
                                                <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                                                Pod Issues ({pod.issues?.length || 0})
                                              </span>
                                              <button
                                                onClick={(e) => {
                                                  e.stopPropagation()
                                                  setExpandedPodIssues(null)
                                                }}
                                                className="text-gray-400 hover:text-gray-600"
                                              >
                                                ×
                                              </button>
                                            </div>
                                            <div className="space-y-2 max-h-64 overflow-y-auto">
                                              {pod.issues && pod.issues.length > 0 ? (
                                                pod.issues.map((issue, idx) => (
                                                  <div key={idx} className={`p-2 rounded ${
                                                    issue.reason === 'CrashLoopBackOff' || issue.reason === 'OOMKilled' || issue.reason === 'Error'
                                                      ? 'bg-red-50 border border-red-200'
                                                      : issue.reason === 'HighRestartCount'
                                                        ? 'bg-orange-50 border border-orange-200'
                                                        : 'bg-amber-50 border border-amber-200'
                                                  }`}>
                                                    <div className="flex items-start gap-2">
                                                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                                                        issue.type === 'container' || issue.type === 'initContainer'
                                                          ? 'bg-blue-100 text-blue-700'
                                                          : issue.type === 'condition'
                                                            ? 'bg-purple-100 text-purple-700'
                                                            : issue.type === 'restarts'
                                                              ? 'bg-orange-100 text-orange-700'
                                                              : 'bg-gray-100 text-gray-700'
                                                      }`}>
                                                        {issue.type === 'initContainer' ? 'init' : issue.type}
                                                      </span>
                                                      <div className="flex-1 min-w-0">
                                                        <div className="font-medium text-gray-900">
                                                          {issue.reason}
                                                          {issue.exitCode !== undefined && (
                                                            <span className="ml-1 text-gray-500">(exit: {issue.exitCode})</span>
                                                          )}
                                                        </div>
                                                        {issue.containerName && (
                                                          <div className="text-gray-500 text-[10px]">
                                                            Container: {issue.containerName}
                                                          </div>
                                                        )}
                                                        {issue.conditionType && (
                                                          <div className="text-gray-500 text-[10px]">
                                                            Condition: {issue.conditionType}
                                                          </div>
                                                        )}
                                                        {issue.message && (
                                                          <div className="mt-1 text-gray-600 break-words">
                                                            {issue.message.length > 150
                                                              ? `${issue.message.substring(0, 150)}...`
                                                              : issue.message}
                                                          </div>
                                                        )}
                                                      </div>
                                                    </div>
                                                  </div>
                                                ))
                                              ) : (
                                                <div className="text-gray-500 italic">
                                                  Pod has issues but no specific details available.
                                                  Check container status and conditions.
                                                </div>
                                              )}
                                            </div>
                                            {/* Show pod conditions if available */}
                                            {pod.conditions && pod.conditions.some(c => c.status === 'False') && (
                                              <div className="mt-3 pt-2 border-t border-gray-100">
                                                <div className="text-[10px] font-semibold text-gray-700 mb-1">Conditions:</div>
                                                <div className="space-y-1">
                                                  {pod.conditions.filter(c => c.status === 'False').map((cond, idx) => (
                                                    <div key={idx} className="flex items-center gap-1 text-[10px]">
                                                      <XCircle className="w-3 h-3 text-red-500" />
                                                      <span className="font-medium">{cond.type}:</span>
                                                      <span className="text-gray-600">{cond.reason || 'Unknown'}</span>
                                                    </div>
                                                  ))}
                                                </div>
                                              </div>
                                            )}
                                          </div>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                </td>
                                <td className="px-5 py-4 text-sm">
                                  <span
                                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md ${
                                      pod.status === 'Running' && pod.ready
                                        ? 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-600/20'
                                        : pod.status === 'Pending'
                                        ? 'bg-amber-50 text-amber-700 ring-1 ring-amber-600/20'
                                        : pod.status === 'Failed' || pod.status === 'Error'
                                        ? 'bg-red-50 text-red-700 ring-1 ring-red-600/20'
                                        : pod.status === 'Succeeded'
                                        ? 'bg-blue-50 text-blue-700 ring-1 ring-blue-600/20'
                                        : 'bg-slate-50 text-slate-600 ring-1 ring-slate-600/20'
                                    }`}
                                  >
                                    <span className={`w-1.5 h-1.5 rounded-full ${
                                      pod.status === 'Running' && pod.ready
                                        ? 'bg-emerald-500'
                                        : pod.status === 'Pending'
                                        ? 'bg-amber-500 animate-pulse'
                                        : pod.status === 'Failed' || pod.status === 'Error'
                                        ? 'bg-red-500'
                                        : pod.status === 'Succeeded'
                                        ? 'bg-blue-500'
                                        : 'bg-slate-400'
                                    }`} />
                                    {pod.status}
                                  </span>
                                </td>
                                <td className="px-5 py-4">
                                  <span className="text-xs text-slate-600 font-mono bg-slate-50 px-2 py-1 rounded">
                                    {pod.nodeName || '-'}
                                  </span>
                                </td>
                                <td className="px-5 py-4">
                                  <span className="text-xs text-slate-600 font-mono bg-slate-50 px-2 py-1 rounded">
                                    {pod.podIP || '-'}
                                  </span>
                                </td>
                                <td className="px-5 py-4">
                                  <div className="space-y-1.5">
                                    {(pod.containers || []).map((container, idx) => (
                                      <div key={idx} className="flex items-center gap-2">
                                        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${
                                          container.ready ? 'bg-emerald-500' : 'bg-red-500'
                                        }`} />
                                        <span className="text-xs font-medium text-slate-700">{container.name}</span>
                                        <span className="text-xs text-slate-400 font-mono truncate max-w-[200px]" title={container.image}>
                                          {container.image.split('/').pop()}
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                </td>
                                <td className="px-5 py-4">
                                  <span className={`inline-flex items-center px-2 py-1 text-xs font-medium rounded ${
                                    (pod.restartCount || 0) === 0
                                      ? 'bg-slate-50 text-slate-600'
                                      : (pod.restartCount || 0) < 5
                                      ? 'bg-amber-50 text-amber-700'
                                      : 'bg-red-50 text-red-700'
                                  }`}>
                                    {pod.restartCount || 0}
                                  </span>
                                </td>
                                <td className="px-5 py-4">
                                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity" onClick={(e) => e.stopPropagation()}>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        setSelectedResource({ type: 'pod', namespace: pod.namespace, name: pod.name })
                                      }}
                                      className="p-1.5 text-slate-500 hover:text-blue-600 hover:bg-blue-50 rounded-md transition-colors"
                                      title="View pod details"
                                    >
                                      <Eye className="w-4 h-4" />
                                    </button>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        setDescribePod({ namespace: pod.namespace, name: pod.name })
                                      }}
                                      className="p-1.5 text-slate-500 hover:text-blue-600 hover:bg-blue-50 rounded-md transition-colors"
                                      title="Describe pod"
                                    >
                                      <Info className="w-4 h-4" />
                                    </button>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        setSelectedLogPod({ namespace: pod.namespace, name: pod.name, container: pod.containers?.[0]?.name })
                                      }}
                                      className="p-2 text-blue-600 hover:text-blue-800 hover:bg-blue-50 rounded transition-colors"
                                      title="View pod logs"
                                    >
                                      <FileText className="w-4 h-4" />
                                    </button>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        if (confirm(`Are you sure you want to delete pod "${pod.name}" in namespace "${pod.namespace}"?`)) {
                                          handleDeleteResource('pods', pod.namespace, pod.name)
                                        }
                                      }}
                                      disabled={isActioning}
                                      className="p-2 text-red-600 hover:text-red-800 hover:bg-red-50 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                      title="Delete pod"
                                    >
                                      <Trash2 className="w-4 h-4" />
                                    </button>
                                  </div>
                                </td>
                              </tr>
                              )
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}

                {/* Services Tab Content */}
                {activeResourceTab === 'services' && (
                  <div>
                    {isLoading ? (
                      <div className="p-12 text-center">
                        <Loader2 className="w-8 h-8 animate-spin mx-auto text-gray-400" />
                        <p className="mt-4 text-gray-500">Loading services...</p>
                      </div>
                    ) : services.length === 0 ? (
                      <div className="p-12 text-center text-gray-500">
                        No services found in namespace &quot;{selectedNamespace}&quot;
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead className="bg-gray-50 border-b border-gray-200">
                            <tr>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Service Name</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Cluster IP</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Ports</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                            </tr>
                          </thead>
                          <tbody className="bg-white divide-y divide-gray-200">
                            {services.map((service) => (
                              <tr 
                                key={service.name} 
                                className="hover:bg-gray-50"
                              >
                                <td
                                  className="px-6 py-4 text-sm font-medium text-gray-900 cursor-pointer"
                                  onClick={() => setSelectedResource({ type: 'service', namespace: service.namespace, name: service.name })}
                                >
                                  {service.name}
                                </td>
                                <td
                                  className="px-6 py-4 text-sm text-gray-600 cursor-pointer"
                                  onClick={() => setSelectedResource({ type: 'service', namespace: service.namespace, name: service.name })}
                                >
                                  {service.type}
                                </td>
                                <td
                                  className="px-6 py-4 text-sm text-gray-600 font-mono text-xs cursor-pointer"
                                  onClick={() => setSelectedResource({ type: 'service', namespace: service.namespace, name: service.name })}
                                >
                                  {service.clusterIP || '-'}
                                </td>
                                <td
                                  className="px-6 py-4 text-sm text-gray-600 cursor-pointer"
                                  onClick={() => setSelectedResource({ type: 'service', namespace: service.namespace, name: service.name })}
                                >
                                  {(service.ports || []).map((port, idx) => (
                                    <div key={idx} className="text-xs">
                                      {port.port}/{port.protocol}
                                    </div>
                                  ))}
                                </td>
                                <td className="px-6 py-4 text-sm" onClick={(e) => e.stopPropagation()}>
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <button
                                      type="button"
                                      onClick={() => setSelectedResource({ type: 'service', namespace: service.namespace, name: service.name })}
                                      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md border border-gray-300"
                                      title="View or edit service"
                                    >
                                      <Settings className="w-3.5 h-3.5" />
                                      Update
                                    </button>
                                    {(service.ports && service.ports.length > 0) ? (
                                      <button
                                        type="button"
                                        onClick={() => {
                                          const firstPort = service.ports[0].port
                                          setPortForwardModal({ service, targetPort: firstPort, localPort: firstPort })
                                          setPortForwardCopied(false)
                                        }}
                                        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-md border border-blue-200"
                                      >
                                        <Network className="w-3.5 h-3.5" />
                                        Port forward
                                      </button>
                                    ) : (
                                      null
                                    )}
                                  </div>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}

                {/* ConfigMaps Tab Content */}
                {activeResourceTab === 'configmaps' && (
                  <div>
                    {isLoading ? (
                      <div className="p-12 text-center">
                        <Loader2 className="w-8 h-8 animate-spin mx-auto text-gray-400" />
                        <p className="mt-4 text-gray-500">Loading configmaps...</p>
                      </div>
                    ) : configmaps.length === 0 ? (
                      <div className="p-12 text-center text-gray-500">
                        No configmaps found in namespace &quot;{selectedNamespace}&quot;
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead className="bg-gray-50 border-b border-gray-200">
                            <tr>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">ConfigMap Name</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Data Keys</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Created</th>
                            </tr>
                          </thead>
                          <tbody className="bg-white divide-y divide-gray-200">
                            {configmaps.map((cm) => (
                              <tr 
                                key={cm.name} 
                                className="hover:bg-gray-50 cursor-pointer"
                                onClick={() => setSelectedResource({ type: 'configmap', namespace: cm.namespace, name: cm.name })}
                              >
                                <td className="px-6 py-4 text-sm font-medium text-gray-900">{cm.name}</td>
                                <td className="px-6 py-4 text-sm text-gray-600">
                                  <div className="flex flex-wrap gap-1">
                                    {Object.keys(cm.data || {}).map((key) => (
                                      <span key={key} className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs">
                                        {key}
                                      </span>
                                    ))}
                                  </div>
                                </td>
                                <td className="px-6 py-4 text-sm text-gray-600">
                                  {cm.creationTimestamp ? new Date(cm.creationTimestamp).toLocaleDateString() : '-'}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}

                {/* Secrets Tab Content */}
                {activeResourceTab === 'secrets' && (
                  <div>
                    <div className="flex justify-end mb-4">
                      <button
                        onClick={() => {
                          setShowCreateSecretModal(true)
                          setCreateSecretName('')
                          setCreateSecretData([{ key: '', value: '' }])
                          setCreateSecretError(null)
                        }}
                        className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-amber-600 hover:bg-amber-700 rounded-md"
                      >
                        <Plus className="w-4 h-4" />
                        Create Secret
                      </button>
                    </div>
                    {isLoading ? (
                      <div className="p-12 text-center">
                        <Loader2 className="w-8 h-8 animate-spin mx-auto text-gray-400" />
                        <p className="mt-4 text-gray-500">Loading secrets...</p>
                      </div>
                    ) : secrets.length === 0 ? (
                      <div className="p-12 text-center text-gray-500">
                        No secrets found in namespace &quot;{selectedNamespace}&quot;
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead className="bg-gray-50 border-b border-gray-200">
                            <tr>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Secret Name</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Keys</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Created</th>
                            </tr>
                          </thead>
                          <tbody className="bg-white divide-y divide-gray-200">
                            {secrets.map((s) => (
                              <tr 
                                key={s.name} 
                                className="hover:bg-gray-50 cursor-pointer"
                                onClick={() => setSelectedResource({ type: 'secret', namespace: s.namespace, name: s.name })}
                              >
                                <td className="px-6 py-4 text-sm font-medium text-gray-900">{s.name}</td>
                                <td className="px-6 py-4 text-sm text-gray-600">{s.type || 'Opaque'}</td>
                                <td className="px-6 py-4 text-sm text-gray-600">
                                  <div className="flex flex-wrap gap-1">
                                    {(s.keys || []).map((key: string) => (
                                      <span key={key} className="px-2 py-1 bg-amber-100 text-amber-800 rounded text-xs">
                                        {key}
                                      </span>
                                    ))}
                                  </div>
                                </td>
                                <td className="px-6 py-4 text-sm text-gray-600">
                                  {s.age ? new Date(s.age).toLocaleDateString() : '-'}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}

                {/* Events Tab Content */}
                {activeResourceTab === 'events' && (
                  <div>
                    {isLoading ? (
                      <div className="p-12 text-center">
                        <Loader2 className="w-8 h-8 animate-spin mx-auto text-gray-400" />
                        <p className="mt-4 text-gray-500">Loading events...</p>
                      </div>
                    ) : events.length === 0 ? (
                      <div className="p-12 text-center text-gray-500">
                        No events found in namespace &quot;{selectedNamespace}&quot;
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead className="bg-gray-50 border-b border-gray-200">
                            <tr>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Object</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Reason</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Message</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Count</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Seen</th>
                            </tr>
                          </thead>
                          <tbody className="bg-white divide-y divide-gray-200">
                            {events.map((event) => (
                              <tr 
                                key={event.name} 
                                className="hover:bg-gray-50 cursor-pointer"
                                onClick={() => setSelectedEvent(event)}
                              >
                                <td className="px-6 py-4 text-sm font-medium text-gray-900">
                                  {event.involvedObject?.kind}/{event.involvedObject?.name}
                                </td>
                                <td className="px-6 py-4 text-sm">
                                  <span
                                    className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                      event.type === 'Warning'
                                        ? 'bg-yellow-100 text-yellow-800'
                                        : 'bg-green-100 text-green-800'
                                    }`}
                                  >
                                    {event.type}
                                  </span>
                                </td>
                                <td className="px-6 py-4 text-sm text-gray-600">{event.reason}</td>
                                <td className="px-6 py-4 text-sm text-gray-600 max-w-md truncate">{event.message}</td>
                                <td className="px-6 py-4 text-sm text-gray-600">{event.count || 0}</td>
                                <td className="px-6 py-4 text-sm text-gray-600">
                                  {event.lastTimestamp ? new Date(event.lastTimestamp).toLocaleString() : '-'}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}

                {/* CronJobs Tab Content */}
                {activeResourceTab === 'cronjobs' && (
                  <div>
                    {isLoading ? (
                      <div className="p-12 text-center">
                        <Loader2 className="w-8 h-8 animate-spin mx-auto text-gray-400" />
                        <p className="mt-4 text-gray-500">Loading cronjobs...</p>
                      </div>
                    ) : cronjobs.length === 0 ? (
                      <div className="p-12 text-center text-gray-500">
                        No cronjobs found in namespace &quot;{selectedNamespace}&quot;
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead className="bg-gray-50 border-b border-gray-200">
                            <tr>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Schedule</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Suspend</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Active</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Schedule</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Containers</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Created</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                            </tr>
                          </thead>
                          <tbody className="bg-white divide-y divide-gray-200">
                            {cronjobs.map((cronjob) => (
                              <tr
                                key={`${cronjob.namespace}/${cronjob.name}`}
                                className="hover:bg-gray-50 cursor-pointer"
                                onClick={() => setSelectedResource({ type: 'cronjob', namespace: cronjob.namespace, name: cronjob.name })}
                              >
                                <td className="px-6 py-4 text-sm font-medium text-gray-900">{cronjob.name}</td>
                                <td className="px-6 py-4 text-sm text-gray-600 font-mono">{cronjob.schedule || '-'}</td>
                                <td className="px-6 py-4 text-sm">
                                  <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${cronjob.suspend ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>
                                    {cronjob.suspend ? 'Yes' : 'No'}
                                  </span>
                                </td>
                                <td className="px-6 py-4 text-sm text-gray-600">{cronjob.active}</td>
                                <td className="px-6 py-4 text-sm text-gray-600">
                                  {cronjob.lastScheduleTime ? new Date(cronjob.lastScheduleTime).toLocaleString() : '-'}
                                </td>
                                <td className="px-6 py-4 text-sm text-gray-600">
                                  <div className="flex flex-col gap-1">
                                    {(cronjob.containers || []).map((container) => (
                                      <span key={container.name} className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs">
                                        {container.name}: {container.image.split(':')[0]}
                                      </span>
                                    ))}
                                  </div>
                                </td>
                                <td className="px-6 py-4 text-sm text-gray-600">
                                  {cronjob.creationTimestamp ? new Date(cronjob.creationTimestamp).toLocaleDateString() : '-'}
                                </td>
                                <td className="px-6 py-4 text-sm text-gray-600">
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      setSelectedResource({ type: 'cronjob', namespace: cronjob.namespace, name: cronjob.name })
                                    }}
                                    className="text-blue-600 hover:text-blue-800 flex items-center gap-1"
                                  >
                                    <Eye className="w-4 h-4" />
                                    View Details
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}

                {/* Jobs Tab Content */}
                {activeResourceTab === 'jobs' && (
                  <div>
                    {isLoading ? (
                      <div className="p-12 text-center">
                        <Loader2 className="w-8 h-8 animate-spin mx-auto text-gray-400" />
                        <p className="mt-4 text-gray-500">Loading jobs...</p>
                      </div>
                    ) : jobs.length === 0 ? (
                      <div className="p-12 text-center text-gray-500">
                        No jobs found in namespace &quot;{selectedNamespace}&quot;
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead className="bg-gray-50 border-b border-gray-200">
                            <tr>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Completions</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Succeeded</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Failed</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Active</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Age</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Containers</th>
                              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                            </tr>
                          </thead>
                          <tbody className="bg-white divide-y divide-gray-200">
                            {jobs.map((job) => {
                              const jobAge = job.startTime ? new Date(job.startTime) : null
                              const ageString = jobAge ? `${Math.floor((Date.now() - jobAge.getTime()) / (1000 * 60))}m` : '-'
                              return (
                                <tr
                                  key={`${job.namespace}/${job.name}`}
                                  className="hover:bg-gray-50 cursor-pointer"
                                  onClick={() => setSelectedResource({ type: 'job', namespace: job.namespace, name: job.name })}
                                >
                                  <td className="px-6 py-4 text-sm font-medium text-gray-900">{job.name}</td>
                                  <td className="px-6 py-4 text-sm text-gray-600">{job.succeeded}/{job.completions}</td>
                                  <td className="px-6 py-4 text-sm">
                                    <span className="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                                      {job.succeeded}
                                    </span>
                                  </td>
                                  <td className="px-6 py-4 text-sm">
                                    {job.failed > 0 ? (
                                      <span className="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">
                                        {job.failed}
                                      </span>
                                    ) : (
                                      <span className="text-gray-600">0</span>
                                    )}
                                  </td>
                                  <td className="px-6 py-4 text-sm">
                                    {job.active > 0 ? (
                                      <span className="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800">
                                        {job.active}
                                      </span>
                                    ) : (
                                      <span className="text-gray-600">0</span>
                                    )}
                                  </td>
                                  <td className="px-6 py-4 text-sm text-gray-600">{ageString}</td>
                                  <td className="px-6 py-4 text-sm text-gray-600">
                                    <div className="flex flex-col gap-1">
                                      {(job.containers || []).map((container) => (
                                        <span key={container.name} className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs">
                                          {container.name}: {container.image.split(':')[0]}
                                        </span>
                                      ))}
                                    </div>
                                  </td>
                                  <td className="px-6 py-4 text-sm text-gray-600">
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        setSelectedResource({ type: 'job', namespace: job.namespace, name: job.name })
                                      }}
                                      className="text-blue-600 hover:text-blue-800 flex items-center gap-1"
                                    >
                                      <Eye className="w-4 h-4" />
                                      View Details
                                    </button>
                                  </td>
                                </tr>
                              )
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}
                  </div>

              {/* Flow Tracing Tab Content */}
              {activeResourceTab === 'flow-tracing' && (
                <div className="w-full">
                  <FlowVisualization
                    apiUrl={apiUrl}
                    namespace={selectedNamespace && selectedNamespace !== 'all' ? selectedNamespace : undefined}
                  />
                </div>
              )}

              {/* Databases Tab Content - only when feature enabled */}
              {enableDatabase && activeResourceTab === 'databases' && (
                <div className="w-full">
                  <DatabaseManagement
                    apiUrl={apiUrl}
                    namespace={selectedNamespace && selectedNamespace !== 'all' ? selectedNamespace : undefined}
                  />
                </div>
              )}

              {/* MongoDB Compass Tab Content */}
              {enableMongoDBWizard && activeResourceTab === 'mongodb-wizard' && (
                <div className="w-full">
                  <MongoDBWizard
                    apiUrl={apiUrl}
                    namespace={selectedNamespace && selectedNamespace !== 'all' ? selectedNamespace : undefined}
                  />
                </div>
              )}

              {/* Adminer Tab Content */}
              {enableAdminerWizard && activeResourceTab === 'adminer-wizard' && (
                <div className="w-full">
                  <AdminerWizard
                    apiUrl={apiUrl}
                    namespace={selectedNamespace && selectedNamespace !== 'all' ? selectedNamespace : undefined}
                  />
                </div>
              )}

              {/* ═══ INGRESSES TAB ═══ */}
              {activeResourceTab === 'ingresses' && (
                <div>
                  {isLoading ? (
                    <div className="p-12 text-center">
                      <Loader2 className="w-8 h-8 animate-spin mx-auto text-gray-400" />
                      <p className="mt-4 text-gray-500">Loading ingresses...</p>
                    </div>
                  ) : ingresses.length === 0 ? (
                    <div className="p-12 text-center text-gray-500">
                      No ingresses found in namespace &quot;{selectedNamespace}&quot;
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full">
                        <thead className="bg-gray-50 border-b border-gray-200">
                          <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Class</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Hosts</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Paths</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Backend</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">TLS</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Age</th>
                          </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                          {ingresses.map((ing) => (
                            <tr key={`${ing.namespace}-${ing.name}`} className="hover:bg-gray-50">
                              <td className="px-6 py-4 text-sm font-medium text-gray-900">{ing.name}</td>
                              <td className="px-6 py-4 text-sm text-gray-600">{ing.ingressClassName || <span className="text-gray-400">—</span>}</td>
                              <td className="px-6 py-4 text-sm text-gray-600">
                                {ing.rules.map((r, i) => <div key={i} className="font-mono text-xs">{r.host}</div>)}
                              </td>
                              <td className="px-6 py-4 text-sm">
                                <div className="flex flex-wrap gap-1">
                                  {ing.rules.flatMap((r, ri) => r.paths.map((p, pi) => (
                                    <span key={`${ri}-${pi}`} className="px-2 py-0.5 bg-blue-100 text-blue-800 rounded text-xs font-mono">{p.path}</span>
                                  )))}
                                </div>
                              </td>
                              <td className="px-6 py-4 text-sm text-gray-600">
                                <div className="space-y-0.5">
                                  {ing.rules.flatMap((r, ri) => r.paths.map((p, pi) => (
                                    p.backend?.serviceName ? <div key={`${ri}-${pi}`} className="text-xs">{p.backend.serviceName}:{p.backend.servicePort}</div> : null
                                  )))}
                                </div>
                              </td>
                              <td className="px-6 py-4 text-sm">
                                {ing.tls && ing.tls.length > 0 ? (
                                  <span className="px-2 py-0.5 bg-green-100 text-green-800 rounded-full text-xs font-semibold">🔒 TLS</span>
                                ) : (
                                  <span className="text-gray-400">—</span>
                                )}
                              </td>
                              <td className="px-6 py-4 text-sm text-gray-500">{ing.creationTimestamp ? timeAgo(ing.creationTimestamp) : '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* ═══ PVCs TAB ═══ */}
              {activeResourceTab === 'pvcs' && (
                <div>
                  {isLoading ? (
                    <div className="p-12 text-center">
                      <Loader2 className="w-8 h-8 animate-spin mx-auto text-gray-400" />
                      <p className="mt-4 text-gray-500">Loading persistent volume claims...</p>
                    </div>
                  ) : pvcs.length === 0 ? (
                    <div className="p-12 text-center text-gray-500">
                      No PVCs found in namespace &quot;{selectedNamespace}&quot;
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full">
                        <thead className="bg-gray-50 border-b border-gray-200">
                          <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Storage Class</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Capacity</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Access Modes</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Volume</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Age</th>
                          </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                          {pvcs.map((pvc) => (
                            <tr key={`${pvc.namespace}-${pvc.name}`} className="hover:bg-gray-50">
                              <td className="px-6 py-4 text-sm font-medium text-gray-900">{pvc.name}</td>
                              <td className="px-6 py-4 text-sm">
                                <span className={`px-2 py-0.5 text-xs font-semibold rounded-full ${
                                  pvc.status === 'Bound' ? 'bg-green-100 text-green-800' :
                                  pvc.status === 'Pending' ? 'bg-yellow-100 text-yellow-800' :
                                  pvc.status === 'Lost' ? 'bg-red-100 text-red-800' :
                                  'bg-gray-100 text-gray-800'
                                }`}>{pvc.status}</span>
                              </td>
                              <td className="px-6 py-4 text-sm text-gray-600">{pvc.storageClassName || <span className="text-gray-400">—</span>}</td>
                              <td className="px-6 py-4 text-sm font-mono text-gray-900">{pvc.capacity || '—'}</td>
                              <td className="px-6 py-4 text-sm">
                                <div className="flex flex-wrap gap-1">
                                  {pvc.accessModes.map((mode) => (
                                    <span key={mode} className="px-2 py-0.5 bg-purple-100 text-purple-800 rounded text-xs">{mode}</span>
                                  ))}
                                </div>
                              </td>
                              <td className="px-6 py-4 text-sm text-gray-500 font-mono text-xs">{pvc.volumeName || '—'}</td>
                              <td className="px-6 py-4 text-sm text-gray-500">{pvc.creationTimestamp ? timeAgo(pvc.creationTimestamp) : '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* Image change report: per-deployment image change count + which images (from cluster) - only when feature enabled */}
              {enableImageChangeReport && activeResourceTab === 'image-change-report' && (
                <div className="w-full">
                  <div className="bg-white rounded-lg border border-gray-200 p-4 sm:p-6">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">Image change report</h3>
                    <p className="text-sm text-gray-600 mb-4">Per deployment: <strong>how many times the image was changed</strong> (count) and <strong>which images</strong> (flow from start to current). Changes made via Selective or Bulk Update in Deployments are reflected here. Download CSV available.</p>
                    {(deployedNamespace || selectedNamespace) && (deployedNamespace || selectedNamespace) !== 'all' ? (
                      <>
                        <div className="flex flex-wrap items-end gap-3 mb-4">
                          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-gray-100 text-sm text-gray-700">
                            <span className="text-xs font-medium text-gray-500">Namespace:</span>
                            <span className="font-medium">{deployedNamespace || selectedNamespace}</span>
                          </div>
                          <button
                            type="button"
                            onClick={loadImageChangeReport}
                            disabled={imageChangeReportLoading}
                            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50"
                          >
                            {imageChangeReportLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <BarChart2 className="w-4 h-4" />}
                            Get report
                          </button>
                        </div>
                        {imageChangeReportData && (
                          <>
                            {/* Current deployment images from cluster - always shown when we have data */}
                            {imageChangeReportData.currentDeployments && imageChangeReportData.currentDeployments.length > 0 && (
                              <div className="border border-gray-200 rounded-lg overflow-hidden mb-6">
                                <div className="px-4 py-2 bg-emerald-50 border-b border-gray-200 flex flex-wrap items-center justify-between gap-2">
                                  <span className="text-sm font-medium text-gray-800">
                                    Current deployment images in namespace <strong>{deployedNamespace || selectedNamespace}</strong> (from cluster — change count & flow from ReplicaSet history)
                                  </span>
                                  <button
                                    type="button"
                                    onClick={() => {
                                      const rows: string[][] = [
                                        ['Deployment', 'Namespace', 'Image changes', 'Revision', 'Date', 'Container', 'Image'],
                                      ];
                                      imageChangeReportData.currentDeployments?.forEach((row) => {
                                        const flow = row.imageFlow || [];
                                        if (flow.length === 0) {
                                          rows.push([row.deployment, row.namespace, String(row.changeCount ?? 0), '-', '-', '-', row.images?.map((i) => i.container ? `${i.container}: ${i.image}` : i.image).join('; ') || '']);
                                        } else {
                                          flow.forEach((rev, idx) => {
                                            const date = rev.createdAt ? new Date(rev.createdAt).toISOString().slice(0, 10) : '-';
                                            rev.images?.forEach((img) => {
                                              rows.push([row.deployment, row.namespace, String(row.changeCount ?? 0), String(rev.revision ?? idx + 1), date, img.container || '-', img.image || '']);
                                            });
                                          });
                                        }
                                      });
                                      const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
                                      const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
                                      const link = document.createElement('a');
                                      link.href = URL.createObjectURL(blob);
                                      link.download = `image-change-report-${deployedNamespace || selectedNamespace}-${imageChangeReportData.date}.csv`;
                                      link.click();
                                      URL.revokeObjectURL(link.href);
                                    }}
                                    className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 text-white text-xs font-medium rounded hover:bg-blue-700"
                                  >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                                    Download CSV
                                  </button>
                                </div>
                                <table className="w-full text-sm">
                                  <thead className="bg-gray-50 border-b border-gray-200">
                                    <tr>
                                      <th className="text-left px-4 py-2 font-medium text-gray-700">Service (Deployment)</th>
                                      <th className="text-right px-4 py-2 font-medium text-gray-700 w-20">Image changes</th>
                                      <th className="text-left px-4 py-2 font-medium text-gray-700">Current image list</th>
                                      <th className="text-left px-4 py-2 font-medium text-gray-700">Flow (start → current)</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-gray-100">
                                    {imageChangeReportData.currentDeployments.map((row, i) => (
                                      <tr key={`${row.namespace}-${row.deployment}-${i}`} className="hover:bg-gray-50">
                                        <td className="px-4 py-2 font-medium text-gray-900">{row.deployment}</td>
                                        <td className="px-4 py-2 text-right font-mono">{row.changeCount ?? 0}</td>
                                        <td className="px-4 py-2 text-gray-600">
                                          <ul className="list-disc list-inside space-y-0.5 max-w-md">
                                            {row.images?.map((img, j) => (
                                              <li key={j} className="font-mono text-xs" title={img.image}>{img.container ? `${img.container}: ${img.image}` : img.image}</li>
                                            ))}
                                          </ul>
                                        </td>
                                        <td className="px-4 py-2 text-gray-600">
                                          {row.imageFlow && row.imageFlow.length > 0 ? (
                                            <div className="flex flex-wrap items-center gap-x-1 gap-y-0.5 max-w-lg">
                                              {row.imageFlow.map((rev, idx) => (
                                                <span key={idx} className="inline-flex items-center gap-0.5">
                                                  {idx > 0 && <span className="text-gray-400">→</span>}
                                                  <span className="font-mono text-xs bg-gray-100 px-1 rounded" title={rev.images?.map((im) => im.image).join(', ')}>
                                                    Rev{rev.revision ?? idx + 1} ({rev.createdAt ? new Date(rev.createdAt).toISOString().slice(0, 10) : '-'}): {rev.images?.map((im) => im.image?.split(':').pop() || im.image).join(', ')}
                                                  </span>
                                                </span>
                                              ))}
                                            </div>
                                          ) : (
                                            <span className="text-gray-400">—</span>
                                          )}
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}

                            {/* Recent Image Changes - Detailed History by Deployment (collapsible) */}
                            {imageChangeReportData.recentInNamespace && imageChangeReportData.recentInNamespace.length > 0 && (() => {
                              const recent = imageChangeReportData.recentInNamespace
                              const byDeployment = recent.reduce((acc: Record<string, typeof recent>, entry) => {
                                const key = entry.deployment || 'unknown'
                                if (!acc[key]) acc[key] = []
                                acc[key].push(entry)
                                return acc
                              }, {})
                              const deploymentNames = Object.keys(byDeployment)
                              const toggleExpanded = (key: string) => {
                                setExpandedImageHistoryDeployments(prev => {
                                  const next = new Set(prev)
                                  if (next.has(key)) next.delete(key)
                                  else next.add(key)
                                  return next
                                })
                              }
                              return (
                              <div className="space-y-2">
                                <div className="px-4 py-2 bg-blue-50 border border-gray-200 rounded-t-lg flex flex-wrap items-center justify-between gap-2">
                                  <span className="text-sm font-medium text-gray-800">
                                    Recent image changes — by deployment ({recent.length} entries)
                                  </span>
                                  <button
                                    type="button"
                                    onClick={() => {
                                      const rows: string[][] = [
                                        ['Date', 'Time', 'Deployment', 'Container', 'Old Image', 'New Image', 'Source', 'Changed By'],
                                      ]
                                      recent.forEach((entry) => {
                                        const dateStr = entry.at ? new Date(entry.at).toLocaleDateString() : entry.date
                                        const timeStr = entry.at ? new Date(entry.at).toLocaleTimeString() : ''
                                        rows.push([
                                          dateStr,
                                          timeStr,
                                          entry.deployment || '',
                                          entry.container || '',
                                          entry.oldImage || '',
                                          entry.image || '',
                                          entry.source === 'ui-single' ? 'UI - Single Edit' : entry.source === 'ui-bulk' ? 'UI - Bulk Update' : entry.source === 'ui-selective' ? 'UI - Selective Update' : entry.source === 'api' ? 'API / Terminal' : entry.source || 'Unknown',
                                          entry.user || 'anonymous',
                                        ])
                                      })
                                      const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n')
                                      const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' })
                                      const link = document.createElement('a')
                                      link.href = URL.createObjectURL(blob)
                                      link.download = `image-change-history-${deployedNamespace || selectedNamespace}-${imageChangeReportData.date}.csv`
                                      link.click()
                                      URL.revokeObjectURL(link.href)
                                    }}
                                    className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 text-white text-xs font-medium rounded hover:bg-blue-700"
                                  >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                                    Download History CSV
                                  </button>
                                </div>
                                {deploymentNames.map((depName) => {
                                  const entries = byDeployment[depName]
                                  const count = entries.length
                                  const isExpanded = expandedImageHistoryDeployments.has(depName)
                                  return (
                                    <div key={depName} className="bg-white border border-gray-200 rounded-lg overflow-hidden">
                                      <button
                                        type="button"
                                        onClick={() => toggleExpanded(depName)}
                                        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-gray-50 transition-colors"
                                      >
                                        <div className="flex items-center gap-2">
                                          <span className="font-semibold text-gray-900">{depName}</span>
                                          <span className="text-xs text-gray-500 bg-gray-100 px-2 py-0.5 rounded-full">
                                            {count} image update{count !== 1 ? 's' : ''}
                                          </span>
                                        </div>
                                        <ChevronDown className={`w-5 h-5 text-gray-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                                      </button>
                                      {isExpanded && (
                                        <div className="border-t border-gray-200">
                                          <table className="w-full text-sm">
                                            <thead className="bg-gray-50 border-b border-gray-200">
                                              <tr>
                                                <th className="text-left px-4 py-2 font-medium text-gray-700">When</th>
                                                <th className="text-left px-4 py-2 font-medium text-gray-700">Deployment</th>
                                                <th className="text-left px-4 py-2 font-medium text-gray-700">Container</th>
                                                <th className="text-left px-4 py-2 font-medium text-gray-700">Old Image → New Image</th>
                                                <th className="text-left px-4 py-2 font-medium text-gray-700">Source</th>
                                                <th className="text-left px-4 py-2 font-medium text-gray-700">Changed By</th>
                                              </tr>
                                            </thead>
                                            <tbody className="divide-y divide-gray-100">
                                              {entries.map((entry, i) => {
                                                const sourceLabel = entry.source === 'ui-single' ? 'UI - Single Edit' : entry.source === 'ui-bulk' ? 'UI - Bulk Update' : entry.source === 'ui-selective' ? 'UI - Selective' : entry.source === 'api' ? 'API / Terminal' : entry.source || 'Unknown'
                                                const sourceBg = entry.source === 'ui-single' ? 'bg-green-100 text-green-800' : entry.source === 'ui-bulk' ? 'bg-purple-100 text-purple-800' : entry.source === 'ui-selective' ? 'bg-blue-100 text-blue-800' : entry.source === 'api' ? 'bg-orange-100 text-orange-800' : 'bg-gray-100 text-gray-700'
                                                return (
                                                  <tr key={i} className="hover:bg-gray-50">
                                                    <td className="px-4 py-2 text-gray-600 whitespace-nowrap">
                                                      <div className="text-xs">{entry.at ? new Date(entry.at).toLocaleDateString() : entry.date}</div>
                                                      <div className="text-xs text-gray-400">{entry.at ? new Date(entry.at).toLocaleTimeString() : ''}</div>
                                                    </td>
                                                    <td className="px-4 py-2 font-medium text-gray-900">{entry.deployment}</td>
                                                    <td className="px-4 py-2 text-gray-600 font-mono text-xs">{entry.container || '—'}</td>
                                                    <td className="px-4 py-2">
                                                      <div className="flex items-center gap-1 flex-wrap">
                                                        {entry.oldImage ? (
                                                          <>
                                                            <span className="font-mono text-xs bg-red-50 text-red-700 px-1.5 py-0.5 rounded" title={entry.oldImage}>{entry.oldImage.length > 40 ? '...' + entry.oldImage.slice(-37) : entry.oldImage}</span>
                                                            <span className="text-gray-400">→</span>
                                                            <span className="font-mono text-xs bg-green-50 text-green-700 px-1.5 py-0.5 rounded" title={entry.image}>{(entry.image || '').length > 40 ? '...' + (entry.image || '').slice(-37) : entry.image}</span>
                                                          </>
                                                        ) : (
                                                          <span className="font-mono text-xs bg-green-50 text-green-700 px-1.5 py-0.5 rounded" title={entry.image}>{(entry.image || '').length > 50 ? '...' + (entry.image || '').slice(-47) : entry.image}</span>
                                                        )}
                                                      </div>
                                                    </td>
                                                    <td className="px-4 py-2">
                                                      <span className={`inline-block text-xs font-medium px-2 py-0.5 rounded-full ${sourceBg}`}>{sourceLabel}</span>
                                                    </td>
                                                    <td className="px-4 py-2 text-gray-600 text-xs">{entry.user || 'anonymous'}</td>
                                                  </tr>
                                                )
                                              })}
                                            </tbody>
                                          </table>
                                        </div>
                                      )}
                                    </div>
                                  )
                                })}
                              </div>
                              )
                            })()}

                            {/* No audit data message */}
                            {imageChangeReportData.recentInNamespace && imageChangeReportData.recentInNamespace.length === 0 && (
                              <div className="border border-gray-200 rounded-lg p-4 text-center text-gray-500 text-sm">
                                No image change history found in audit logs. Changes made via the UI will appear here after you update images.
                              </div>
                            )}
                          </>
                        )}
                      </>
                    ) : (
                      <div className="py-6 text-center text-gray-500 text-sm">
                        Connect to the cluster to see the image change report for your deployed namespace.
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Download Images - Auto Excel Download */}
              {activeResourceTab === 'download-images' && (() => {
                // Auto-trigger Excel download when this tab is selected
                const downloadImagesExcel = () => {
                  // Find max containers in any deployment
                  const maxContainers = Math.max(...deployments.map(d => d.containers.length), 1)

                  // Build header with Container 1, Container 2, Container 3 columns
                  const header = ['S.No', 'Deployment', 'Namespace']
                  for (let i = 1; i <= maxContainers; i++) {
                    header.push(`Container ${i} Name`, `Container ${i} Image`, `Container ${i} Tag`)
                  }

                  const rows: string[][] = [header]

                  let sno = 1
                  deployments.forEach(d => {
                    const row: string[] = [
                      String(sno++),
                      d.name,
                      d.namespace
                    ]

                    // Add each container in separate columns
                    for (let i = 0; i < maxContainers; i++) {
                      if (d.containers[i]) {
                        const imageParts = d.containers[i].image.split(':')
                        const imageName = imageParts[0]
                        const imageTag = imageParts[1] || 'latest'
                        row.push(d.containers[i].name, imageName, imageTag)
                      } else {
                        row.push('', '', '')
                      }
                    }

                    rows.push(row)
                  })

                  // Convert to CSV format (Excel compatible)
                  const csvContent = rows.map(row =>
                    row.map(cell => `"${cell.replace(/"/g, '""')}"`).join(',')
                  ).join('\n')

                  // Create and download file
                  const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' })
                  const link = document.createElement('a')
                  const url = URL.createObjectURL(blob)
                  link.setAttribute('href', url)
                  link.setAttribute('download', `${selectedNamespace}-images-${new Date().toISOString().split('T')[0]}.csv`)
                  link.style.visibility = 'hidden'
                  document.body.appendChild(link)
                  link.click()
                  document.body.removeChild(link)

                  // Switch back to deployments tab after download
                  setTimeout(() => setActiveResourceTab('deployments'), 100)
                }

                // Trigger download immediately
                setTimeout(downloadImagesExcel, 100)

                return (
                  <div className="w-full p-6 flex items-center justify-center min-h-[300px]">
                    <div className="text-center">
                      <div className="w-16 h-16 mx-auto mb-4 bg-green-100 rounded-full flex items-center justify-center">
                        <svg className="w-8 h-8 text-green-600 animate-bounce" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                        </svg>
                      </div>
                      <h3 className="text-lg font-semibold text-gray-900 mb-2">Downloading Images List...</h3>
                      <p className="text-gray-600">
                        Exporting {deployments.reduce((acc, d) => acc + d.containers.length, 0)} container images from <strong>{selectedNamespace}</strong> namespace
                      </p>
                    </div>
                  </div>
                )
              })()}

            </div>
          </div>
        )}
      </div>

      {/* Old Pods Table - Removed (now in tabbed pane) */}
      {false && isConnected && selectedNamespace && showPods && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden mb-6">
          <div className="px-6 py-4 border-b border-gray-200 bg-gradient-to-r from-orange-50 to-amber-50 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-800">
              Pods ({pods.length}) {selectedNamespace === 'all' ? '- All Namespaces' : `- Namespace: ${selectedNamespace}`}
            </h3>
            <button
              onClick={() => setShowPods(false)}
              className="text-gray-500 hover:text-gray-700 px-3 py-1 text-sm"
            >
              Hide
            </button>
          </div>

          {isLoading ? (
            <div className="p-12 text-center">
              <Loader2 className="w-8 h-8 animate-spin mx-auto text-gray-400" />
              <p className="mt-4 text-gray-500">Loading pods...</p>
            </div>
          ) : pods.length === 0 ? (
            <div className="p-12 text-center text-gray-500">
              No pods found {selectedNamespace === 'all' ? 'in any namespace' : `in namespace "${selectedNamespace}"`}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    {selectedNamespace === 'all' && (
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        Namespace
                      </th>
                    )}
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                      Pod Name
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                      Node
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                      Pod IP
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                      Containers
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                      Restarts
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {pods.map((pod) => (
                    <tr key={`${pod.namespace}-${pod.name}`} className="hover:bg-gray-50">
                      {selectedNamespace === 'all' && (
                        <td className="px-6 py-4 text-sm font-medium text-gray-700">
                          {pod.namespace}
                        </td>
                      )}
                      <td className="px-6 py-4 text-sm font-medium text-gray-900">
                        <div className="flex items-center gap-2">
                          {pod.name}
                          {pod.hasIssues && (
                            <div className="relative">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  const podKey = `${pod.namespace}-${pod.name}`
                                  setExpandedPodIssues(expandedPodIssues === podKey ? null : podKey)
                                }}
                                className="p-1 text-amber-500 hover:text-amber-600 hover:bg-amber-50 rounded transition-colors"
                                title="View pod issues"
                              >
                                <AlertTriangle className="w-4 h-4" />
                              </button>
                              {expandedPodIssues === `${pod.namespace}-${pod.name}` && (
                                <div className="absolute z-50 left-0 top-8 w-80 bg-white border border-gray-200 rounded-lg shadow-xl p-3 text-xs">
                                  <div className="flex items-center justify-between mb-2 pb-2 border-b border-gray-100">
                                    <span className="font-semibold text-gray-900 flex items-center gap-1">
                                      <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                                      Pod Issues ({pod.issues?.length || 0})
                                    </span>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        setExpandedPodIssues(null)
                                      }}
                                      className="text-gray-400 hover:text-gray-600"
                                    >
                                      ×
                                    </button>
                                  </div>
                                  <div className="space-y-2 max-h-64 overflow-y-auto">
                                    {pod.issues && pod.issues.length > 0 ? (
                                      pod.issues.map((issue, idx) => (
                                        <div key={idx} className={`p-2 rounded ${
                                          issue.reason === 'CrashLoopBackOff' || issue.reason === 'OOMKilled' || issue.reason === 'Error'
                                            ? 'bg-red-50 border border-red-200'
                                            : issue.reason === 'HighRestartCount'
                                              ? 'bg-orange-50 border border-orange-200'
                                              : 'bg-amber-50 border border-amber-200'
                                        }`}>
                                          <div className="flex items-start gap-2">
                                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                                              issue.type === 'container' || issue.type === 'initContainer'
                                                ? 'bg-blue-100 text-blue-700'
                                                : issue.type === 'condition'
                                                  ? 'bg-purple-100 text-purple-700'
                                                  : issue.type === 'restarts'
                                                    ? 'bg-orange-100 text-orange-700'
                                                    : 'bg-gray-100 text-gray-700'
                                            }`}>
                                              {issue.type === 'initContainer' ? 'init' : issue.type}
                                            </span>
                                            <div className="flex-1 min-w-0">
                                              <div className="font-medium text-gray-900">
                                                {issue.reason}
                                                {issue.exitCode !== undefined && (
                                                  <span className="ml-1 text-gray-500">(exit: {issue.exitCode})</span>
                                                )}
                                              </div>
                                              {issue.containerName && (
                                                <div className="text-gray-500 text-[10px]">
                                                  Container: {issue.containerName}
                                                </div>
                                              )}
                                              {issue.conditionType && (
                                                <div className="text-gray-500 text-[10px]">
                                                  Condition: {issue.conditionType}
                                                </div>
                                              )}
                                              {issue.message && (
                                                <div className="mt-1 text-gray-600 break-words">
                                                  {issue.message.length > 150
                                                    ? `${issue.message.substring(0, 150)}...`
                                                    : issue.message}
                                                </div>
                                              )}
                                            </div>
                                          </div>
                                        </div>
                                      ))
                                    ) : (
                                      <div className="text-gray-500 italic">
                                        Pod has issues but no specific details available.
                                        Check container status and conditions.
                                      </div>
                                    )}
                                  </div>
                                  {/* Show pod conditions if available */}
                                  {pod.conditions && pod.conditions.some(c => c.status === 'False') && (
                                    <div className="mt-3 pt-2 border-t border-gray-100">
                                      <div className="text-[10px] font-semibold text-gray-700 mb-1">Conditions:</div>
                                      <div className="space-y-1">
                                        {pod.conditions.filter(c => c.status === 'False').map((cond, idx) => (
                                          <div key={idx} className="flex items-center gap-1 text-[10px]">
                                            <XCircle className="w-3 h-3 text-red-500" />
                                            <span className="font-medium">{cond.type}:</span>
                                            <span className="text-gray-600">{cond.reason || 'Unknown'}</span>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <span
                          className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                            pod.status === 'Running' && pod.ready
                              ? 'bg-green-100 text-green-800'
                              : pod.status === 'Pending'
                              ? 'bg-yellow-100 text-yellow-800'
                              : pod.status === 'Failed' || pod.status === 'Error'
                              ? 'bg-red-100 text-red-800'
                              : 'bg-gray-100 text-gray-800'
                          }`}
                        >
                          {pod.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600 font-mono text-xs">
                        {pod.nodeName || '-'}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600 font-mono text-xs">
                        {pod.podIP || '-'}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600">
                        <div className="space-y-1">
                          {(pod.containers || []).map((container, idx) => (
                            <div key={idx} className="text-xs">
                              <span className="font-medium">{container.name}:</span>{' '}
                              <span className="font-mono">{container.image}</span>
                              {container.ready !== undefined && (
                                <span
                                  className={`ml-2 px-1 py-0.5 rounded text-xs ${
                                    container.ready
                                      ? 'bg-green-100 text-green-700'
                                      : 'bg-red-100 text-red-700'
                                  }`}
                                >
                                  {container.ready ? '✓' : '✗'}
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600">
                        {pod.restartCount || 0}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => {
                              setErrorMessage(`Viewing pod: ${pod.name} - Status: ${pod.status}`)
                              setTimeout(() => setErrorMessage(null), 3000)
                            }}
                            className="p-2 text-gray-600 hover:text-gray-800 hover:bg-gray-50 rounded transition-colors"
                            title="View pod details"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}


      {/* Services Table with Edit */}
      {/* Old Services Table - Removed (now in tabbed pane) */}
      {false && isConnected && selectedNamespace && showServices && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden mb-6">
          <div className="px-6 py-4 border-b border-gray-200 bg-gradient-to-r from-indigo-50 to-purple-50 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-800">
              Services ({services.length}) {selectedNamespace === 'all' ? '- All Namespaces' : `- Namespace: ${selectedNamespace}`}
            </h3>
            <button
              onClick={() => setShowServices(false)}
              className="text-gray-500 hover:text-gray-700 px-3 py-1 text-sm"
            >
              Hide
            </button>
          </div>

          {isLoading ? (
            <div className="p-12 text-center">
              <Loader2 className="w-8 h-8 animate-spin mx-auto text-gray-400" />
              <p className="mt-4 text-gray-500">Loading services...</p>
            </div>
          ) : services.length === 0 ? (
            <div className="p-12 text-center text-gray-500">
              No services found {selectedNamespace === 'all' ? 'in any namespace' : `in namespace "${selectedNamespace}"`}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    {selectedNamespace === 'all' && (
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        Namespace
                      </th>
                    )}
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                      Service
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                      Type
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                      Cluster IP
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                      Ports
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                      Selector
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {services.map((service) => (
                    <tr key={`${service.namespace}-${service.name}`} className="hover:bg-gray-50">
                      {selectedNamespace === 'all' && (
                        <td className="px-6 py-4 text-sm font-medium text-gray-700">
                          {service.namespace}
                        </td>
                      )}
                      <td className="px-6 py-4 text-sm font-medium text-gray-900">
                        {service.name}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600">
                        <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs">
                          {service.type}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600 font-mono text-xs">
                        {service.clusterIP || '-'}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600">
                        {(service.ports || []).map((port, idx) => (
                          <div key={idx} className="text-xs">
                            {port.port}:{port.targetPort}/{port.protocol}
                            {port.name && ` (${port.name})`}
                          </div>
                        ))}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600">
                        <div className="flex flex-wrap gap-1">
                          {Object.entries(service.selector).map(([key, value]) => (
                            <span
                              key={key}
                              className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs"
                            >
                              {key}={value}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Port Forward Modal (OpenLens-style) */}
      {portForwardModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div className="fixed inset-0 bg-gray-500 bg-opacity-75" onClick={() => setPortForwardModal(null)} />
            <div className="relative bg-white rounded-xl shadow-xl max-w-md w-full p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Network className="w-5 h-5 text-blue-600" />
                  <h3 className="text-lg font-semibold text-gray-900">Port forward</h3>
                </div>
                <button type="button" onClick={() => setPortForwardModal(null)} className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg">
                  <X className="w-5 h-5" />
                </button>
              </div>
              <p className="text-sm text-gray-600 mb-4">
                <span className="font-medium text-gray-900">{portForwardModal.service.name}</span>
                <span className="text-gray-500"> · </span>
                <span className="text-gray-500">{portForwardModal.service.namespace}</span>
              </p>

              <div className="space-y-4 mb-5">
                <div>
                  <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Target port (service)</label>
                  <select
                    value={portForwardModal.targetPort}
                    onChange={(e) => setPortForwardModal({ ...portForwardModal, targetPort: Number(e.target.value) })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-sm"
                  >
                    {(portForwardModal.service.ports || []).map((p, idx) => (
                      <option key={idx} value={p.port}>{p.port}/{p.protocol}{p.name ? ` (${p.name})` : ''}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Local port</label>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={portForwardModal.localPort}
                    onChange={(e) => setPortForwardModal({ ...portForwardModal, localPort: Number(e.target.value) || portForwardModal.targetPort })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-sm"
                  />
                </div>
              </div>

              <a
                href={`${apiUrl}/k8s/services/${encodeURIComponent(portForwardModal.service.namespace)}/${encodeURIComponent(portForwardModal.service.name)}/proxy/?port=${portForwardModal.targetPort}`}
                target="_blank"
                rel="noopener noreferrer"
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-3 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm mb-4"
              >
                <ExternalLink className="w-4 h-4" />
                Open in browser (no kubectl)
              </a>

              <div className="bg-gray-50 rounded-lg p-3">
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Or run in terminal</p>
                <div className="flex gap-2">
                  <code className="flex-1 px-3 py-2 bg-white border border-gray-200 rounded text-xs font-mono text-gray-800 break-all">
                    kubectl port-forward -n {portForwardModal.service.namespace} svc/{portForwardModal.service.name} {portForwardModal.localPort}:{portForwardModal.targetPort}
                  </code>
                  <button
                    type="button"
                    onClick={() => {
                      const cmd = `kubectl port-forward -n ${portForwardModal.service.namespace} svc/${portForwardModal.service.name} ${portForwardModal.localPort}:${portForwardModal.targetPort}`
                      navigator.clipboard.writeText(cmd).then(() => {
                        setPortForwardCopied(true)
                        setTimeout(() => setPortForwardCopied(false), 2000)
                      })
                    }}
                    className="flex-shrink-0 inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-white bg-gray-700 hover:bg-gray-800 rounded-lg"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    {portForwardCopied ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Resource Detail Modal */}
      <ResourceDetailModal
        isOpen={selectedResource !== null}
        onClose={() => setSelectedResource(null)}
        resourceType={selectedResource?.type || null}
        namespace={selectedResource?.namespace || ''}
        name={selectedResource?.name || ''}
        apiUrl={apiUrl}
        onResourceDeleted={loadData}
      />

      {/* Describe Pod Modal */}
      {describePod && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div className="fixed inset-0 bg-gray-500 bg-opacity-75" onClick={() => setDescribePod(null)} aria-hidden />
            <div className="relative bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] flex flex-col my-8">
              <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">
                  Describe Pod: {describePod.name}
                  <span className="text-sm font-normal text-gray-500 ml-2">({describePod.namespace})</span>
                </h3>
                <button
                  type="button"
                  onClick={() => setDescribePod(null)}
                  className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100"
                  aria-label="Close"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="flex-1 overflow-auto p-4 bg-slate-50">
                {describePodLoading && (
                  <div className="flex items-center justify-center py-12">
                    <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
                  </div>
                )}
                {describePodError && (
                  <p className="text-red-600 text-sm">{describePodError}</p>
                )}
                {!describePodLoading && !describePodError && describePodContent && (
                  <pre className="text-xs font-mono text-slate-800 whitespace-pre-wrap break-words p-4 bg-white border border-gray-200 rounded-lg overflow-x-auto">
                    {describePodContent}
                  </pre>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Create Secret Modal */}
      {showCreateSecretModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div className="fixed inset-0 bg-gray-500 bg-opacity-75" onClick={() => setShowCreateSecretModal(false)} />
            <div className="relative bg-white rounded-lg shadow-xl max-w-lg w-full p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Create Secret</h3>
              <p className="text-sm text-gray-500 mb-4">
                Namespace: <strong>{selectedNamespace}</strong> (key-value pairs are stored as base64)
              </p>
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-1">Secret name</label>
                <input
                  type="text"
                  value={createSecretName}
                  onChange={(e) => setCreateSecretName(e.target.value)}
                  placeholder="my-secret"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-amber-500 focus:border-amber-500"
                />
              </div>
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-2">Data (key-value)</label>
                {createSecretData.map((row, idx) => (
                  <div key={idx} className="flex gap-2 mb-2">
                    <input
                      type="text"
                      value={row.key}
                      onChange={(e) => {
                        const next = [...createSecretData]
                        next[idx] = { ...next[idx], key: e.target.value }
                        setCreateSecretData(next)
                      }}
                      placeholder="key"
                      className="flex-1 px-3 py-2 border border-gray-300 rounded-md text-sm font-mono"
                    />
                    <input
                      type="text"
                      value={row.value}
                      onChange={(e) => {
                        const next = [...createSecretData]
                        next[idx] = { ...next[idx], value: e.target.value }
                        setCreateSecretData(next)
                      }}
                      placeholder="value"
                      className="flex-1 px-3 py-2 border border-gray-300 rounded-md text-sm font-mono"
                    />
                    <button
                      type="button"
                      onClick={() => setCreateSecretData(createSecretData.filter((_, i) => i !== idx))}
                      className="p-2 text-red-500 hover:bg-red-50 rounded"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
                <button
                  type="button"
                  onClick={() => setCreateSecretData([...createSecretData, { key: '', value: '' }])}
                  className="text-sm text-amber-600 hover:text-amber-700 flex items-center gap-1"
                >
                  <Plus className="w-4 h-4" />
                  Add key-value
                </button>
              </div>
              {createSecretError && (
                <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-md text-sm text-red-700">
                  {createSecretError}
                </div>
              )}
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => setShowCreateSecretModal(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md"
                >
                  Cancel
                </button>
                <button
                  disabled={createSecretSaving || !createSecretName.trim() || !selectedNamespace || selectedNamespace === 'all'}
                  onClick={async () => {
                    if (selectedNamespace === 'all' || !selectedNamespace) return
                    const data: Record<string, string> = {}
                    createSecretData.forEach(({ key, value }) => {
                      const k = key.trim()
                      if (k) data[k] = value
                    })
                    if (Object.keys(data).length === 0) {
                      setCreateSecretError('Add at least one key-value pair')
                      return
                    }
                    setCreateSecretError(null)
                    setCreateSecretSaving(true)
                    try {
                      const res = await fetch(`${apiUrl}/k8s/secrets`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ namespace: selectedNamespace, name: createSecretName.trim(), data }),
                      })
                      const json = await res.json()
                      if (json.success) {
                        setShowCreateSecretModal(false)
                        loadData()
                      } else {
                        setCreateSecretError(json.message || 'Failed to create secret')
                      }
                    } catch (e: any) {
                      setCreateSecretError(e.message || 'Failed to create secret')
                    } finally {
                      setCreateSecretSaving(false)
                    }
                  }}
                  className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-amber-600 hover:bg-amber-700 rounded-md disabled:opacity-50"
                >
                  {createSecretSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                  Create
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {selectedLogPod && (
        <PodLogsModal
          isOpen={!!selectedLogPod}
          onClose={() => setSelectedLogPod(null)}
          podName={selectedLogPod.name}
          namespace={selectedLogPod.namespace}
          container={selectedLogPod.container}
          apiUrl={apiUrl}
        />
      )}

      {/* Event Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="relative bg-white rounded-lg shadow-xl max-w-2xl w-[90vw] max-h-[85vh] overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Event Details</h3>
                <p className="text-sm text-gray-500">
                  {selectedEvent.involvedObject?.kind}/{selectedEvent.involvedObject?.name}
                </p>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-gray-500 hover:text-gray-700"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 overflow-auto max-h-[70vh] space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-50 rounded-lg p-3">
                  <label className="text-xs font-medium text-gray-500 uppercase">Type</label>
                  <div className="mt-1">
                    <span className={`px-2 py-1 inline-flex text-sm font-semibold rounded-full ${
                      selectedEvent.type === 'Warning' 
                        ? 'bg-yellow-100 text-yellow-800' 
                        : 'bg-green-100 text-green-800'
                    }`}>
                      {selectedEvent.type}
                    </span>
                  </div>
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <label className="text-xs font-medium text-gray-500 uppercase">Reason</label>
                  <p className="mt-1 text-sm font-medium text-gray-900">{selectedEvent.reason}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <label className="text-xs font-medium text-gray-500 uppercase">Count</label>
                  <p className="mt-1 text-sm font-medium text-gray-900">{selectedEvent.count || 1}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <label className="text-xs font-medium text-gray-500 uppercase">Source</label>
                  <p className="mt-1 text-sm font-medium text-gray-900">
                    {selectedEvent.source?.component || '-'} / {selectedEvent.source?.host || '-'}
                  </p>
                </div>
              </div>
              
              <div className="bg-gray-50 rounded-lg p-3">
                <label className="text-xs font-medium text-gray-500 uppercase">Message</label>
                <p className="mt-1 text-sm text-gray-900 whitespace-pre-wrap">{selectedEvent.message}</p>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-50 rounded-lg p-3">
                  <label className="text-xs font-medium text-gray-500 uppercase">First Timestamp</label>
                  <p className="mt-1 text-sm text-gray-900">
                    {selectedEvent.firstTimestamp ? new Date(selectedEvent.firstTimestamp).toLocaleString() : '-'}
                  </p>
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <label className="text-xs font-medium text-gray-500 uppercase">Last Timestamp</label>
                  <p className="mt-1 text-sm text-gray-900">
                    {selectedEvent.lastTimestamp ? new Date(selectedEvent.lastTimestamp).toLocaleString() : '-'}
                  </p>
                </div>
              </div>
              
              <div className="bg-gray-50 rounded-lg p-3">
                <label className="text-xs font-medium text-gray-500 uppercase">Involved Object</label>
                <div className="mt-1 text-sm text-gray-900">
                  <p><span className="font-medium">Kind:</span> {selectedEvent.involvedObject?.kind}</p>
                  <p><span className="font-medium">Name:</span> {selectedEvent.involvedObject?.name}</p>
                  <p><span className="font-medium">Namespace:</span> {selectedEvent.involvedObject?.namespace}</p>
                  {selectedEvent.involvedObject?.uid && (
                    <p><span className="font-medium">UID:</span> <code className="text-xs bg-gray-200 px-1 rounded">{selectedEvent.involvedObject.uid}</code></p>
                  )}
                </div>
              </div>
              
              {selectedEvent.name && (
                <div className="bg-gray-50 rounded-lg p-3">
                  <label className="text-xs font-medium text-gray-500 uppercase">Event Name</label>
                  <p className="mt-1 text-sm text-gray-900 font-mono">{selectedEvent.name}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Bulk Update Image Wizard Modal */}
      {showBulkUpdateWizard && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="relative bg-white rounded-lg shadow-xl max-w-4xl w-[90vw] max-h-[85vh] overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Bulk Image Update Wizard</h3>
                <p className="text-sm text-gray-500">
                  {bulkUpdateStep === 'select' 
                    ? 'Step 1: Select deployments to update' 
                    : 'Step 2: Review and apply updates'}
                </p>
              </div>
              <button
                onClick={() => {
                  setShowBulkUpdateWizard(false)
                  setBulkUpdateSelections(new Set())
                  setBulkUpdateImage('')
                  setBulkUpdateTagOnly(false)
                  setBulkUpdateActiveTab('')
                  setBulkUpdateContainerImages(new Map())
                  setBulkUpdateContainerTagOnly(new Map())
                  setBulkUpdateStep('select')
                }}
                className="text-gray-500 hover:text-gray-700"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 overflow-auto max-h-[65vh]">
              {bulkUpdateStep === 'select' ? (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={bulkUpdateSelections.size === deployments.length && deployments.length > 0}
                        onChange={handleSelectAllBulkUpdate}
                        className="w-4 h-4"
                      />
                      <span className="font-medium text-gray-700">
                        Select All ({bulkUpdateSelections.size}/{deployments.length} selected)
                      </span>
                    </label>
                    <div className="text-sm text-gray-500">
                      {bulkUpdateSelections.size} deployment(s) selected
                    </div>
                  </div>

                  <div className="border border-gray-200 rounded-lg overflow-hidden">
                    <table className="w-full text-sm">
                      <thead className="bg-gray-50 border-b border-gray-200">
                        <tr>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-12"></th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Deployment</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Containers</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Current Images</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200">
                        {deployments.map((deployment) => {
                          const key = `${deployment.namespace}/${deployment.name}`
                          const isSelected = bulkUpdateSelections.has(key)
                          return (
                            <tr key={key} className={isSelected ? 'bg-blue-50' : 'hover:bg-gray-50'}>
                              <td className="px-4 py-3">
                                <input
                                  type="checkbox"
                                  checked={isSelected}
                                  onChange={() => toggleBulkUpdateSelection(deployment.namespace, deployment.name)}
                                  className="w-4 h-4"
                                />
                              </td>
                              <td className="px-4 py-3">
                                <div className="font-medium text-gray-900">{deployment.name}</div>
                                <div className="text-xs text-gray-500">{deployment.namespace}</div>
                              </td>
                              <td className="px-4 py-3">
                                <div className="space-y-1">
                                  {(deployment.containers || []).map((container, idx) => (
                                    <div key={idx} className="text-xs text-gray-600">
                                      {container.name}
                                    </div>
                                  ))}
                                </div>
                              </td>
                              <td className="px-4 py-3">
                                <div className="space-y-1">
                                  {(deployment.containers || []).map((container, idx) => (
                                    <div key={idx} className="text-xs font-mono text-gray-600">
                                      {container.image}
                                    </div>
                                  ))}
                                </div>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>

                  {/* Container Tabs Section - Only show if deployments are selected */}
                  {bulkUpdateSelections.size > 0 && (() => {
                    // Group all containers by type (sidecar vs main)
                    const mainContainers: Array<{
                      deployment: Deployment
                      container: { name: string; image: string }
                    }> = []
                    const sidecarContainers: Array<{
                      deployment: Deployment
                      container: { name: string; image: string }
                    }> = []

                    deployments.forEach((deployment) => {
                      const key = `${deployment.namespace}/${deployment.name}`
                      if (bulkUpdateSelections.has(key)) {
                        deployment.containers.forEach((container) => {
                          const isSidecar = container.name.toLowerCase().includes('sidecar')
                          if (isSidecar) {
                            sidecarContainers.push({ deployment, container })
                          } else {
                            mainContainers.push({ deployment, container })
                          }
                        })
                      }
                    })

                    // Set initial active tab if not set
                    if (!bulkUpdateActiveTab) {
                      if (mainContainers.length > 0) {
                        setBulkUpdateActiveTab('main')
                      } else if (sidecarContainers.length > 0) {
                        setBulkUpdateActiveTab('sidecar')
                      }
                    }

                    const isActiveSidecar = bulkUpdateActiveTab === 'sidecar'
                    const activeContainers = isActiveSidecar ? sidecarContainers : mainContainers
                    const activeImage = bulkUpdateContainerImages.get(bulkUpdateActiveTab) || ''
                    const activeTagOnly = bulkUpdateContainerTagOnly.get(bulkUpdateActiveTab) || false

                    return (
                      <div className="mt-6 space-y-4">
                        {/* Container Type Tabs */}
                        <div className="border-b border-gray-200">
                          <div className="flex items-center gap-2 overflow-x-auto">
                            {mainContainers.length > 0 && (
                              <button
                                onClick={() => setBulkUpdateActiveTab('main')}
                                className={`px-4 py-2 text-sm font-medium whitespace-nowrap transition-colors ${
                                  bulkUpdateActiveTab === 'main'
                                    ? 'text-blue-600 border-b-2 border-blue-600'
                                    : 'text-gray-600 hover:text-gray-900 hover:border-b-2 hover:border-gray-300'
                                }`}
                              >
                                Main Containers ({mainContainers.length})
                              </button>
                            )}
                            {sidecarContainers.length > 0 && (
                              <button
                                onClick={() => setBulkUpdateActiveTab('sidecar')}
                                className={`px-4 py-2 text-sm font-medium whitespace-nowrap transition-colors ${
                                  bulkUpdateActiveTab === 'sidecar'
                                    ? 'text-blue-600 border-b-2 border-blue-600'
                                    : 'text-gray-600 hover:text-gray-900 hover:border-b-2 hover:border-gray-300'
                                } bg-purple-50`}
                              >
                                Sidecar Containers ({sidecarContainers.length})
                              </button>
                            )}
                          </div>
                        </div>

                        {/* Selected Container Type's Deployments Table */}
                        {activeContainers.length > 0 && (
                          <div className="border border-gray-200 rounded-lg overflow-hidden">
                            <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                              <span className="text-sm font-medium text-gray-700">
                                {isActiveSidecar ? 'Sidecar' : 'Main'} Containers ({activeContainers.length} total)
                              </span>
                            </div>
                            <table className="w-full text-sm">
                              <thead className="bg-gray-50 border-b border-gray-200">
                                <tr>
                                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Deployment</th>
                                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Namespace</th>
                                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Container Name</th>
                                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Current Image</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-gray-200">
                                {activeContainers.map((item, idx) => (
                                  <tr key={`${item.deployment.namespace}/${item.deployment.name}/${item.container.name}-${idx}`} className="hover:bg-gray-50">
                                    <td className="px-4 py-3">
                                      <div className="font-medium text-gray-900">{item.deployment.name}</div>
                                    </td>
                                    <td className="px-4 py-3">
                                      <div className="text-xs text-gray-500">{item.deployment.namespace}</div>
                                    </td>
                                    <td className="px-4 py-3">
                                      <div className="text-xs text-gray-600">{item.container.name}</div>
                                    </td>
                                    <td className="px-4 py-3">
                                      <div className="text-xs font-mono text-gray-600">{item.container.image}</div>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}

                        {/* Image Input Section - Different for sidecar vs main containers */}
                        <div className="mt-4 space-y-3">
                          <div className="flex items-center gap-2">
                            <input
                              type="checkbox"
                              id={`bulkUpdateTagOnly-${bulkUpdateActiveTab}`}
                              checked={activeTagOnly}
                              onChange={(e) => {
                                const newMap = new Map(bulkUpdateContainerTagOnly)
                                newMap.set(bulkUpdateActiveTab, e.target.checked)
                                setBulkUpdateContainerTagOnly(newMap)
                              }}
                              className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                            />
                            <label htmlFor={`bulkUpdateTagOnly-${bulkUpdateActiveTab}`} className="text-sm font-medium text-gray-700 cursor-pointer">
                              Update tag only (keep base image/service name)
                            </label>
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">
                              {activeTagOnly ? 'New Tag:' : 'New Image:'}
                            </label>
                            <input
                              type="text"
                              value={activeImage}
                              onChange={(e) => {
                                const newMap = new Map(bulkUpdateContainerImages)
                                newMap.set(bulkUpdateActiveTab, e.target.value)
                                setBulkUpdateContainerImages(newMap)
                              }}
                              placeholder={activeTagOnly ? "e.g., 1.12.0-rc5 or latest" : "e.g., nginx:1.25 or myregistry.io/app:v2.0"}
                              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                            />
                            {activeTagOnly && (
                              <p className="mt-1 text-xs text-gray-500">
                                Only the tag portion will be updated. Base image will remain unchanged.
                              </p>
                            )}
                          </div>
                        </div>
                      </div>
                    )
                  })()}
                </div>
              ) : (
                <div className="space-y-4">
                  {(() => {
                    // Group all containers by type (sidecar vs main)
                    const mainContainers: Array<{
                      deployment: Deployment
                      container: { name: string; image: string }
                    }> = []
                    const sidecarContainers: Array<{
                      deployment: Deployment
                      container: { name: string; image: string }
                    }> = []

                    deployments.forEach((deployment) => {
                      const key = `${deployment.namespace}/${deployment.name}`
                      if (bulkUpdateSelections.has(key)) {
                        deployment.containers.forEach((container) => {
                          const isSidecar = container.name.toLowerCase().includes('sidecar')
                          if (isSidecar) {
                            sidecarContainers.push({ deployment, container })
                          } else {
                            mainContainers.push({ deployment, container })
                          }
                        })
                      }
                    })

                    const isActiveSidecar = bulkUpdateActiveTab === 'sidecar'
                    const activeContainers = isActiveSidecar ? sidecarContainers : mainContainers
                    const activeImage = bulkUpdateContainerImages.get(bulkUpdateActiveTab) || ''
                    const activeTagOnly = bulkUpdateContainerTagOnly.get(bulkUpdateActiveTab) || false

                    return (
                      <>
                        {/* Container Type Tabs */}
                        <div className="border-b border-gray-200">
                          <div className="flex items-center gap-2 overflow-x-auto">
                            {mainContainers.length > 0 && (
                              <button
                                onClick={() => setBulkUpdateActiveTab('main')}
                                className={`px-4 py-2 text-sm font-medium whitespace-nowrap transition-colors ${
                                  bulkUpdateActiveTab === 'main'
                                    ? 'text-blue-600 border-b-2 border-blue-600'
                                    : 'text-gray-600 hover:text-gray-900 hover:border-b-2 hover:border-gray-300'
                                }`}
                              >
                                Main Containers ({mainContainers.length})
                              </button>
                            )}
                            {sidecarContainers.length > 0 && (
                              <button
                                onClick={() => setBulkUpdateActiveTab('sidecar')}
                                className={`px-4 py-2 text-sm font-medium whitespace-nowrap transition-colors ${
                                  bulkUpdateActiveTab === 'sidecar'
                                    ? 'text-blue-600 border-b-2 border-blue-600'
                                    : 'text-gray-600 hover:text-gray-900 hover:border-b-2 hover:border-gray-300'
                                } bg-purple-50`}
                              >
                                Sidecar Containers ({sidecarContainers.length})
                              </button>
                            )}
                          </div>
                        </div>

                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                          <h4 className="font-medium text-blue-900 mb-2">Update Summary</h4>
                          <div className="text-sm text-blue-800">
                            <p>• {bulkUpdateSelections.size} deployment(s) selected</p>
                            <p>• Container Type: <span className="font-mono">{isActiveSidecar ? 'Sidecar' : 'Main'}</span></p>
                            <p>• Containers to update: {activeContainers.length}</p>
                            <p>• New {activeTagOnly ? 'tag' : 'image'}: <span className="font-mono">{activeImage}</span></p>
                          </div>
                        </div>

                        <div className="border border-gray-200 rounded-lg overflow-hidden">
                          <div className="overflow-x-auto">
                            <table className="w-full text-sm">
                              <thead className="bg-gray-50 border-b border-gray-200">
                                <tr>
                                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Deployment</th>
                                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Namespace</th>
                                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Container Name</th>
                                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Current Image</th>
                                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase min-w-[300px]">New Image</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-gray-200">
                                {activeContainers.map((item, idx) => {
                                  const newImage = activeTagOnly 
                                    ? applyTagOnlyUpdate(item.container.image, activeImage.trim())
                                    : activeImage.trim()
                                  return (
                                    <tr key={`${item.deployment.name}-${item.container.name}-${idx}`} className="hover:bg-gray-50">
                                      <td className="px-4 py-3 text-gray-900">{item.deployment.name}</td>
                                      <td className="px-4 py-3 text-gray-900">{item.deployment.namespace}</td>
                                      <td className="px-4 py-3 text-gray-900">{item.container.name}</td>
                                      <td className="px-4 py-3 font-mono text-xs text-gray-600 break-all">{item.container.image}</td>
                                      <td className="px-4 py-3 font-mono text-xs text-blue-700 font-medium break-all whitespace-normal" title={newImage}>
                                        {newImage}
                                      </td>
                                    </tr>
                                  )
                                })}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      </>
                    )
                  })()}
                </div>
              )}
            </div>

            <div className="px-6 py-4 border-t border-gray-200 flex items-center justify-between">
              <button
                onClick={() => {
                  if (bulkUpdateStep === 'preview') {
                    setBulkUpdateStep('select')
                  } else {
                    setShowBulkUpdateWizard(false)
                    setBulkUpdateSelections(new Set())
                    setBulkUpdateImage('')
                    setBulkUpdateTagOnly(false)
                    setBulkUpdateActiveTab('')
                    setBulkUpdateContainerImages(new Map())
                    setBulkUpdateContainerTagOnly(new Map())
                  }
                }}
                className="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300 transition-colors"
              >
                {bulkUpdateStep === 'preview' ? 'Back' : 'Cancel'}
              </button>
              <div className="flex items-center gap-2">
                {bulkUpdateStep === 'select' ? (
                  <button
                    onClick={() => {
                      if (bulkUpdateSelections.size === 0) {
                        setErrorMessage('Please select at least one deployment')
                        return
                      }
                      if (!bulkUpdateActiveTab || (bulkUpdateActiveTab !== 'main' && bulkUpdateActiveTab !== 'sidecar')) {
                        setErrorMessage('Please select a container tab (Main or Sidecar)')
                        return
                      }
                      const containerImage = bulkUpdateContainerImages.get(bulkUpdateActiveTab) || ''
                      const containerTagOnly = bulkUpdateContainerTagOnly.get(bulkUpdateActiveTab) || false
                      if (!containerImage.trim()) {
                        setErrorMessage('Please enter a new ' + (containerTagOnly ? 'tag' : 'image') + ' for ' + bulkUpdateActiveTab + ' containers')
                        return
                      }
                      setBulkUpdateStep('preview')
                    }}
                    disabled={bulkUpdateSelections.size === 0 || !bulkUpdateActiveTab || (bulkUpdateActiveTab !== 'main' && bulkUpdateActiveTab !== 'sidecar') || !(bulkUpdateContainerImages.get(bulkUpdateActiveTab) || '').trim()}
                    className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Next: Review
                  </button>
                ) : (
                  <button
                    onClick={handleBulkUpdateApply}
                    disabled={isUpdating}
                    className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                  >
                    {isUpdating ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Updating...
                      </>
                    ) : (
                      <>
                        <CheckCircle className="w-4 h-4" />
                        Apply Updates
                      </>
                    )}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Image comparison modal */}
      {showImageComparison && (
        <div className="fixed inset-0 z-40 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black bg-opacity-40"
            onClick={() => setShowImageComparison(false)}
          />
          <div className="relative bg-white rounded-lg shadow-xl max-w-5xl w-[90vw] max-h-[80vh] overflow-hidden z-50">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Image update review</h3>
                <p className="text-sm text-gray-500">
                  Compare current vs new images before applying updates
                </p>
              </div>
              <button
                onClick={() => setShowImageComparison(false)}
                className="text-gray-500 hover:text-gray-700"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 overflow-auto max-h-[70vh]">
              {imageUpdates.size === 0 ? (
                <p className="text-sm text-gray-500">No pending image updates.</p>
              ) : (
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 border-b border-gray-200">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Namespace</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Deployment</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Container</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Current Image</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">New Image</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {Array.from(imageUpdates.values()).map((update, idx) => (
                      <tr key={idx} className="hover:bg-gray-50">
                        <td className="px-4 py-3 text-gray-900">{update.namespace}</td>
                        <td className="px-4 py-3 text-gray-900">{update.deployment}</td>
                        <td className="px-4 py-3 text-gray-900">{update.container}</td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-600">{update.originalImage}</td>
                        <td className="px-4 py-3 font-mono text-xs text-blue-700">{update.image}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
            <div className="px-6 py-4 border-t border-gray-200 flex items-center justify-between">
              <span className="text-sm text-gray-600">
                {imageUpdates.size} change(s) ready to apply
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowImageComparison(false)}
                  className="px-4 py-2 text-sm text-gray-700 border border-gray-300 rounded-md hover:bg-gray-50"
                >
                  Close
                </button>
                <button
                  onClick={() => {
                    setShowImageComparison(false)
                    handleUpdateImages()
                  }}
                  disabled={isUpdating || imageUpdates.size === 0}
                  className="flex items-center gap-2 px-5 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors disabled:opacity-50"
                >
                  {isUpdating ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Applying...
                    </>
                  ) : (
                    <>
                      <Save className="w-4 h-4" />
                      Apply now
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Action Confirmation Modals */}
      {actionModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
            <div className="fixed inset-0 transition-opacity bg-gray-500 bg-opacity-75" onClick={() => setActionModal(null)}></div>

            <div className="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
              <div className="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg leading-6 font-medium text-gray-900">
                    {actionModal.type === 'scale' && 'Scale Deployment'}
                    {actionModal.type === 'restart' && 'Restart Deployment'}
                    {actionModal.type === 'delete' && 'Delete Resource'}
                  </h3>
                  <button
                    onClick={() => setActionModal(null)}
                    className="text-gray-400 hover:text-gray-500"
                  >
                    <XCircle className="h-6 w-6" />
                  </button>
                </div>

                {actionModal.type === 'scale' && (
                  <div>
                    <p className="text-sm text-gray-500 mb-4">
                      Scale deployment <strong>{actionModal.name}</strong> in namespace <strong>{actionModal.namespace}</strong>
                    </p>
                    <div className="flex items-center gap-4">
                      <button
                        onClick={() => setScaleReplicas(Math.max(0, scaleReplicas - 1))}
                        className="p-2 border border-gray-300 rounded-md hover:bg-gray-50"
                      >
                        <Minus className="w-4 h-4" />
                      </button>
                      <input
                        type="number"
                        min="0"
                        value={scaleReplicas}
                        onChange={(e) => setScaleReplicas(Math.max(0, parseInt(e.target.value) || 0))}
                        className="w-20 px-3 py-2 border border-gray-300 rounded-md text-center focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                      <button
                        onClick={() => setScaleReplicas(scaleReplicas + 1)}
                        className="p-2 border border-gray-300 rounded-md hover:bg-gray-50"
                      >
                        <Plus className="w-4 h-4" />
                      </button>
                      <span className="text-sm text-gray-600">replicas</span>
                    </div>
                    {actionModal.currentReplicas !== undefined && (
                      <p className="text-xs text-gray-500 mt-2">
                        Current: {actionModal.currentReplicas} replicas
                      </p>
                    )}
                  </div>
                )}

                {actionModal.type === 'restart' && (
                  <div>
                    <p className="text-sm text-gray-500 mb-4">
                      Are you sure you want to restart deployment <strong>{actionModal.name}</strong> in namespace <strong>{actionModal.namespace}</strong>?
                    </p>
                    <p className="text-xs text-gray-400">
                      This will trigger a rolling restart of all pods in the deployment.
                    </p>
                  </div>
                )}

                {actionModal.type === 'delete' && (
                  <div>
                    <div className="flex items-center gap-3 mb-4">
                      <AlertTriangle className="w-6 h-6 text-red-600" />
                      <p className="text-sm text-gray-700">
                        Are you sure you want to delete <strong>{actionModal.resourceType}</strong> <strong>{actionModal.name}</strong> in namespace <strong>{actionModal.namespace}</strong>?
                      </p>
                    </div>
                    <p className="text-xs text-red-600 font-medium">
                      This action cannot be undone!
                    </p>
                  </div>
                )}

                <div className="mt-6 flex justify-end gap-3">
                  <button
                    onClick={() => setActionModal(null)}
                    className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                    disabled={isActioning}
                  >
                    Cancel
                  </button>
                  <button
                    onClick={async () => {
                      if (!actionModal) return
                      
                      if (actionModal.type === 'scale') {
                        await handleScaleDeployment(actionModal.namespace, actionModal.name, scaleReplicas)
                      } else if (actionModal.type === 'restart') {
                        await handleRestartDeployment(actionModal.namespace, actionModal.name)
                      } else if (actionModal.type === 'delete') {
                        await handleDeleteResource(actionModal.resourceType, actionModal.namespace, actionModal.name)
                      }
                    }}
                    disabled={isActioning}
                    className={`px-4 py-2 rounded-md text-sm font-medium text-white ${
                      actionModal.type === 'delete'
                        ? 'bg-red-600 hover:bg-red-700'
                        : 'bg-blue-600 hover:bg-blue-700'
                    } disabled:opacity-50 disabled:cursor-not-allowed`}
                  >
                    {isActioning ? (
                      <>
                        <Loader2 className="w-4 h-4 inline animate-spin mr-2" />
                        Processing...
                      </>
                    ) : (
                      <>
                        {actionModal.type === 'scale' && 'Scale'}
                        {actionModal.type === 'restart' && 'Restart'}
                        {actionModal.type === 'delete' && 'Delete'}
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
      {/* ═══ GLOBAL SEARCH MODAL (Cmd+K) ═══ */}
      {showSearchModal && (
        <div className="fixed inset-0 z-[100] flex items-start justify-center pt-[12vh]">
          <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={() => setShowSearchModal(false)} />
          <div className="relative bg-white rounded-xl shadow-2xl max-w-2xl w-[90vw] max-h-[60vh] overflow-hidden z-[101] border border-gray-200">
            <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-200">
              <Search className="w-5 h-5 text-gray-400" />
              <input
                autoFocus
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search deployments, pods, services, databases, events..."
                className="flex-1 text-sm text-gray-900 placeholder-gray-400 bg-transparent outline-none"
              />
              <kbd className="hidden sm:inline-flex items-center px-2 py-1 text-xs font-medium text-gray-400 bg-gray-100 border border-gray-200 rounded">ESC</kbd>
            </div>
            <div className="overflow-y-auto max-h-[50vh] p-2">
              {searchQuery.trim() === '' ? (
                <div className="p-8 text-center text-sm text-gray-400">
                  <Search className="w-8 h-8 mx-auto mb-2 text-gray-300" />
                  Type to search across all resource types...
                </div>
              ) : searchResults.length === 0 ? (
                <div className="p-8 text-center text-sm text-gray-400">No results for &quot;{searchQuery}&quot;</div>
              ) : (
                <div className="space-y-0.5">
                  {searchResults.map((result, idx) => (
                    <button
                      key={`${result.type}-${result.name}-${idx}`}
                      onClick={() => {
                        setActiveResourceTab(result.tabKey as typeof activeResourceTab)
                        // Only open detail modal for resource types that support it
                        if (result.resourceType !== 'event' && result.resourceType !== 'database') {
                          setSelectedResource({ type: result.resourceType as any, namespace: result.namespace, name: result.name })
                        }
                        setShowSearchModal(false)
                      }}
                      className="w-full flex items-center gap-3 px-3 py-2.5 text-sm rounded-lg hover:bg-gray-100 text-left transition-colors"
                    >
                      <span className={`px-2 py-0.5 text-xs font-medium rounded min-w-[80px] text-center ${
                        result.type === 'Deployment' ? 'bg-blue-100 text-blue-700' :
                        result.type === 'Pod' ? 'bg-emerald-100 text-emerald-700' :
                        result.type === 'Service' ? 'bg-purple-100 text-purple-700' :
                        result.type === 'ConfigMap' ? 'bg-cyan-100 text-cyan-700' :
                        result.type === 'Secret' ? 'bg-amber-100 text-amber-700' :
                        result.type === 'CronJob' ? 'bg-orange-100 text-orange-700' :
                        result.type === 'Job' ? 'bg-teal-100 text-teal-700' :
                        result.type === 'Ingress' ? 'bg-indigo-100 text-indigo-700' :
                        result.type === 'PVC' ? 'bg-pink-100 text-pink-700' :
                        result.type === 'Node' ? 'bg-slate-100 text-slate-700' :
                        result.type === 'Event' ? 'bg-red-100 text-red-700' :
                        result.type === 'Database' ? 'bg-violet-100 text-violet-700' :
                        'bg-gray-100 text-gray-700'
                      }`}>{result.type}</span>
                      <span className="font-medium text-gray-900 truncate">{result.name}</span>
                      <span className="text-xs text-gray-400 ml-auto flex-shrink-0">{result.namespace}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
