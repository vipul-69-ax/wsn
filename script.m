numNodes = 100;
gridSize = 200;
transmissionRange = 30;
simulationDuration = 200;
initialEnergy = 2000;
numEntries = 10;
nodeMobility = 5;

nodePositions = gridSize * rand(numNodes, 2);

simulationResults = table('Size', [0, 9], 'VariableNames', {'Node', 'AttackType', 'TimeStep', 'InitialEnergy', 'EnergyLevel', 'EnergyDrained', 'ActualEnergyConsumed', 'ActualAttackSuccessRate', 'AttackDuration'}, 'VariableTypes', {'double', 'char', 'double', 'double', 'double', 'double', 'double', 'double', 'double'});

figure;
scatter(nodePositions(:,1), nodePositions(:,2), 'filled');
title('WSN Topology');
xlabel('X-axis');
ylabel('Y-axis');
axis equal;

for entryIndex = 1:numEntries
    attackNode = randi(numNodes);
    attackType = generateRandomAttackType();
    
    nodePositions = updateNodePositions(nodePositions, nodeMobility);
    
    energyLevels = initializeEnergyLevels(numNodes, initialEnergy);
    
    attackDuration = randi([10, 50]);
    
    for t = 1:simulationDuration
        disp(['Entry ' num2str(entryIndex) ', Attack Type: ' attackType ', Time Step ' num2str(t)]);
        
        if t <= attackDuration
            energyConsumptionRate = calculateDynamicEnergyConsumption(nodePositions, attackNode, transmissionRange);
            
            for i = 1:numNodes
                if i == attackNode
                    continue;
                end
                
                if isNodeInRange(nodePositions, i, attackNode, transmissionRange)
                    disp(['Node ' num2str(i) ' transmitted data.']);
                    
                    [energyConsumed, energyDrained] = simulateEnergyConsumption(initialEnergy, energyLevels(i), transmissionRange, distance(nodePositions(i,:), nodePositions(attackNode,:)));
                    energyLevels(i) = energyLevels(i) - energyConsumed;
                    
                    actualAttackSuccessRate = calculateActualAttackSuccessRate(attackType, energyConsumed);
                    
                    newRow = createSimulationRow(i, attackType, t, initialEnergy, energyLevels(i), energyDrained, energyConsumed, actualAttackSuccessRate, attackDuration);
                    simulationResults = [simulationResults; newRow];
                end
            end
        end
        
        energyLevels = updateEnergyLevels(energyLevels, calculateIdleEnergyConsumption(energyLevels));
    end
end

saveSimulationResults(simulationResults, 'wsn_attack_simulation_results_enhanced.csv');

function energyConsumptionRate = calculateDynamicEnergyConsumption(nodePositions, attackNode, transmissionRange)
    distanceToAttackNode = distance(nodePositions, nodePositions(attackNode, :));
    energyConsumptionRate = exp(-distanceToAttackNode / transmissionRange);
end

function [energyConsumed, energyDrained] = simulateEnergyConsumption(initialEnergy, currentEnergy, transmissionRange, distanceToAttackNode)
    transmissionLoss = exp(-distanceToAttackNode / transmissionRange);
    energyConsumed = min(currentEnergy, initialEnergy * (1 - transmissionLoss));
    energyDrained = currentEnergy - (currentEnergy - energyConsumed);
end

function idleEnergyConsumption = calculateIdleEnergyConsumption(energyLevels)
    idleEnergyConsumption = mean(energyLevels) * 0.002;
end

function actualAttackSuccessRate = calculateActualAttackSuccessRate(attackType, energyConsumed)
    actualAttackSuccessRate = 1 - exp(-energyConsumed / 100);
end

function attackType = generateRandomAttackType()
    attackTypes = {'Sinkhole', 'Blackhole', 'Sybil', 'Wormhole', 'PhysicalCapture', 'Jamming', 'Spoofing', 'BatteryExhaustion', 'DenialOfService', 'Grayhole'};
    attackType = attackTypes{randi(length(attackTypes))};
end

function highlightAttackNode(nodePositions, attackNode, transmissionRange)
    hold on;
    circle(nodePositions(attackNode, 1), nodePositions(attackNode, 2), transmissionRange, 'r');
end

function inRange = isNodeInRange(nodePositions, node1, node2, range)
    inRange = distance(nodePositions(node1,:), nodePositions(node2,:)) <= range;
end

function updatedPositions = updateNodePositions(nodePositions, mobility)
    updatedPositions = nodePositions + mobility * randn(size(nodePositions));
end

function energyLevels = initializeEnergyLevels(numNodes, initialEnergy)
    energyLevels = ones(1, numNodes) * initialEnergy;
end

function updatedEnergyLevels = updateEnergyLevels(energyLevels, idleEnergyConsumption)
    updatedEnergyLevels = energyLevels - idleEnergyConsumption;
end

function newRow = createSimulationRow(node, attackType, timeStep, initialEnergy, energyLevel, energyDrained, energyConsumed, attackSuccessRate, attackDuration)
    newRow = {node, attackType, timeStep, initialEnergy, energyLevel, energyDrained, energyConsumed, attackSuccessRate, attackDuration};
end

function d = distance(p1, p2)
    d = sqrt(sum((p1 - p2).^2));
end

function saveSimulationResults(simulationResults, filename)
    randomFilename = fullfile(['simulation_results_' num2str(randi(1000)) '.csv']);
    writetable(simulationResults, randomFilename, 'WriteRowNames', false);
end