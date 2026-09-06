// Provenance: amitknigam84/lensops loadNamespaces (vuln).
// repo: amitknigam84/lensops
// commit: 9b87ecc3a44a7fe2a5185cca1fe52441647d5748
// parent: 9b87ecc3a44a7fe2a5185cca1fe52441647d5748
// commit_url: https://github.com/amitknigam84/lensops/commit/fe49109aedfe21dea4d24d4d9f2fa3f1ecfb6c84
// cve: 
// license: MIT
// function: loadNamespaces
// relpath: components/KubernetesManagement.tsx
// provenance: agent
// mechanism: missing_auth_guard
// upstream_start: 805

  const loadNamespaces = async (skipConnectionCheck = false) => {
    if (!skipConnectionCheck && !isConnected) {
      setErrorMessage('Please connect to a Kubernetes cluster first')
      return
    }
    
    setIsLoading(true)
    setErrorMessage(null)
    
    try {
      console.log('📋 Loading namespaces from:', `${apiUrl}/k8s/namespaces`)
      const response = await fetch(`${apiUrl}/k8s/namespaces`)
      
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

        try {
          await loadNamespaces(true)
          await loadData()
        } catch (err) {
          console.error('Error loading namespaces:', err)
        }
        try {
          await loadNamespaces(true)
          // Always load data after namespaces are loaded (defaults to 'all' to show all resources)
          await loadData()
        } catch (err) {
          console.error('Error loading namespaces after connection:', err)
          setErrorMessage('✅ Connected, but failed to load namespaces. Click "Load Namespaces" to retry.')
        }
      if (apiUrl && !deployedNamespace) {
        loadNamespaces(true)
      }
    if (apiUrl && !isConnected && !isConnecting) {
      console.log('🚀 Auto-connecting to Kubernetes cluster via ServiceAccount...')
      loadNamespaces(true) // Skip connection check since we're auto-connecting
    }
    if (apiUrl && !isConnected) {
      loadNamespaces(true);
    }
